#!/usr/bin/env python3
# Copyright 2026 uds-takserver authors
# SPDX-License-Identifier: GPL-3.0-only
"""Fork-only, native-amd64 historical GEOS trial. Raw logs stay private to the job."""
import email.utils
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import shlex
import shutil
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
APT_OPTIONS = ['-o', 'Acquire::Check-Date=true', '-o', 'Acquire::Check-Valid-Until=true',
               '-o', 'Acquire::Max-ValidTime=7776000', '-o', 'Acquire::AllowInsecureRepositories=false',
               '-o', 'Acquire::AllowDowngradeToInsecureRepositories=false',
               '-o', 'APT::Get::AllowUnauthenticated=false', '-o', 'Acquire::ForceHash=SHA256',
               '-o', 'APT::Update::Error-Mode=any']
SOURCES = '''Types: deb
URIs: http://deb.debian.org/debian
Suites: trixie trixie-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: http://security.debian.org/debian-security
Suites: trixie-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
'''


class Rejected(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise Rejected(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def paragraphs(raw):
    values = []
    for block in raw.decode().strip().split('\n\n'):
        item = {}
        for line in block.splitlines():
            if line and not line[0].isspace() and ': ' in line:
                key, value = line.split(': ', 1)
                require(key not in item, 'duplicate_package_field')
                item[key] = value
        if item:
            values.append(item)
    return values


def package_matches(raw, expected):
    candidates = [item for item in paragraphs(raw) if item.get('Package') == expected['Package']
                  and item.get('Version') == expected['Version']]
    require(candidates, 'exact_current_package_missing')
    require(all(all(item.get(k) == v for k, v in expected.items()) for item in candidates), 'current_package_identity_changed')
    return expected


def download_plan(raw, maximum):
    result = []
    for line in raw.decode().splitlines():
        if not line.startswith("'"):
            continue
        values = shlex.split(line)
        require(len(values) == 4, 'invalid_apt_download_plan')
        uri, name, size, digest = values
        from urllib.parse import urlsplit
        parsed = urlsplit(uri)
        require(parsed.scheme in ('http', 'https') and parsed.hostname in ('deb.debian.org', 'security.debian.org')
                and parsed.port is None and not parsed.username and not parsed.password
                and parsed.path.startswith(('/debian/pool/', '/debian-security/pool/'))
                and re.fullmatch(r'[A-Za-z0-9_+.~%:-]+\.deb', name)
                and size.isdigit() and int(size) > 0 and re.fullmatch(r'SHA256:[0-9a-f]{64}', digest),
                'unapproved_apt_payload')
        result.append({'uri': uri, 'filename': name, 'bytes': int(size), 'sha256': digest[7:]})
    require(result and len(result) <= 160 and len({x['filename'] for x in result}) == len(result), 'empty_or_duplicate_download_plan')
    require(sum(x['bytes'] for x in result) <= maximum, 'package_download_bound')
    return result


def release_identity(raw, now):
    require(raw.startswith(b'-----BEGIN PGP SIGNED MESSAGE-----\n'), 'signed_release_envelope_required')
    candidates = [item for item in paragraphs(raw) if item.get('Origin') == 'Debian']
    require(len(candidates) == 1, 'release_metadata_missing')
    fields = candidates[0]
    require(fields.get('Origin') == 'Debian' and fields.get('Codename') in ('trixie', 'trixie-updates', 'trixie-security'), 'wrong_signed_release')
    date = email.utils.parsedate_to_datetime(fields['Date']).timestamp()
    require(date <= now + 10 and now - date <= 7776000, 'release_date_not_current')
    expiry = fields.get('Valid-Until')
    if expiry:
        require(now <= email.utils.parsedate_to_datetime(expiry).timestamp(), 'expired_release')
    require(fields['Codename'] == 'trixie' or expiry is not None, 'missing_rolling_release_expiry')
    return {'codename': fields['Codename'], 'date': fields['Date'], 'valid_until': expiry,
            'bytes': len(raw), 'sha256': sha(raw)}


IDENTITY = r'''
import hashlib,json,pathlib,shutil,subprocess
def run(*args):
 return subprocess.check_output(args,stderr=subprocess.STDOUT,timeout=30).decode().strip()
def file(path):
 p=pathlib.Path(path).resolve();return {'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
tools={}
for n,p in [('cc','gcc-14'),('cxx','g++-14'),('make','make'),('readelf','readelf'),('ar','ar'),('ranlib','ranlib'),('patch','patch'),('ldd','ldd'),('python3','python3'),('fixture_cxx','c++')]:
 tools[n]={**file(shutil.which(p)),'version':run(p,'--version')}
assert all(tools[n]['version'].splitlines()[0].endswith(' 14.2.0') for n in ('cc','cxx','fixture_cxx'))
assert tools['make']['version'].splitlines()[0]=='GNU Make 4.4.1'
assert all(tools[n]['version'].splitlines()[0].endswith(' 2.44') for n in ('readelf','ar','ranlib'))
assert run('gcc-14','-dumpmachine')=='x86_64-linux-gnu'
helpers={}
for n in ('cc1','cc1plus','as','ld','collect2','lto-wrapper'):
 p=run('g++-14','-print-prog-name='+n);helpers[n]=file(p if pathlib.Path(p).is_absolute() else shutil.which(p))
packages=[]
for line in run('dpkg-query','-W','-f=${binary:Package}\t${Version}\t${Architecture}\n').splitlines():
 n,v,a=line.split(chr(9));packages.append({'package':n,'version':v,'architecture':a})
print(json.dumps({'tools':tools,'compiler_helpers':helpers,'installed_packages':packages,'dpkg_status':file('/var/lib/dpkg/status'),'debian_keyring':file('/usr/share/keyrings/debian-archive-keyring.gpg')}))
'''


def main():
    work = Path(os.environ['RUNNER_TEMP']) / 'geos-680'
    require(not work.exists(), 'trial_output_must_be_new')
    work.mkdir()
    evidence = work / 'evidence'; evidence.mkdir()
    private = work / 'private'; private.mkdir()
    lock = json.loads((HERE / 'lock.json').read_text())
    run_id, attempt = os.environ.get('GITHUB_RUN_ID', ''), os.environ.get('GITHUB_RUN_ATTEMPT', '')
    require(run_id.isdigit() and attempt.isdigit(), 'missing_hosted_identity')
    suffix = run_id + '-' + attempt
    builder, consumer = 'geos-680-builder-' + suffix, 'geos-680-proof-' + suffix
    env = dict(os.environ)
    env['DOCKER_CONFIG'] = str(private / 'docker-config')
    env['DOCKER_HOST'] = 'unix:///var/run/docker.sock'
    env.pop('DOCKER_CONTEXT', None)
    Path(env['DOCKER_CONFIG']).mkdir()
    (Path(env['DOCKER_CONFIG']) / 'config.json').write_text('{"auths":{}}\n')
    commands = []
    containers = []
    started = time.monotonic()
    receipt = {'schema':'uds-geos-680-hosted-result-v1','status':'failed','run_id':run_id,'run_attempt':attempt,
               'source_commit':lock['source_commit'],'native_amd64_component_behavior':False,
               'trusted_publisher_acceptance':False,'sdk_acceptance':False,'security_acceptance':False,
               'upstream_required_checks_satisfied':False,'raw_logs_in_artifact':False}

    def write(name, value):
        raw = (json.dumps(value, indent=2) + '\n').encode()
        require(len(raw) <= 8 * 1024 ** 2, 'metadata_artifact_bound')
        (evidence / name).write_bytes(raw)

    def run(args, name, timeout=120):
        require(time.monotonic() - started < 2100, 'trial_deadline')
        path = private / (name + '.log')
        require(not path.exists(), 'duplicate_command_name')
        def limits():
            resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 ** 2, 16 * 1024 ** 2))
        with path.open('xb') as stream:
            child = subprocess.Popen(list(map(str, args)), cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                     stdout=stream, stderr=subprocess.STDOUT, start_new_session=True, preexec_fn=limits)
            try:
                code = child.wait(timeout=min(timeout, max(1, 2100 - (time.monotonic() - started))))
            except subprocess.TimeoutExpired:
                child.kill(); child.wait()
                raise Rejected('command_timeout_' + name) from None
        raw = path.read_bytes()
        commands.append({'name':name,'returncode':code,'bytes':len(raw),'sha256':sha(raw)})
        require(code == 0, 'command_failed_' + name)
        return raw

    def docker(*args, name, timeout=120):
        return run(['docker', *args], name, timeout)

    def execute(*args, name, timeout=120):
        return docker('exec', builder, *args, name=name, timeout=timeout)

    try:
        require(os.environ.get('GITHUB_REPOSITORY') == lock['repository'] and os.environ.get('GITHUB_REF') == 'refs/heads/' + lock['branch'], 'fork_branch_only')
        require((platform.system(), platform.machine()) == ('Linux', 'x86_64'), 'native_amd64_host_only')
        require(shutil.disk_usage(work).free >= 4 * 1024**3, 'host_disk_preflight')
        for name, expected in lock['source_sha256'].items():
            require(sha((ROOT / name).read_bytes()) == expected, 'source_bytes_changed')
        head = run(['git','rev-parse','HEAD'], 'git-head').decode().strip()
        require(head == os.environ.get('GITHUB_SHA') and not run(['git','status','--porcelain','--untracked-files=no'], 'git-clean'), 'checkout_identity')
        run(['git','merge-base','--is-ancestor',lock['source_commit'],'HEAD'], 'source-ancestry')
        trial_files = ['.github/workflows/geos-680-proof.yaml', *[str(p.relative_to(ROOT)) for p in sorted(HERE.glob('*')) if p.is_file()]]
        source = {'head':head,'implementation_and_helpers':lock['source_sha256'],
                  'trial_files':{n:sha((ROOT/n).read_bytes()) for n in trial_files}, 'base_source':lock['source_commit']}
        write('source-identity.json', source)
        host = json.loads(docker('info','--format','{{json .}}', name='docker-info'))
        require(host['OSType'] == 'linux' and host['Architecture'] in ('x86_64','amd64'), 'native_docker_daemon_only')
        image = 'docker.io/library/debian@' + lock['base_manifest_digest']
        docker('pull','--platform','linux/amd64', image, name='base-pull', timeout=300)
        base = json.loads(docker('image','inspect', image, name='base-inspect'))[0]
        require(base['Id'] == lock['base_config_digest'] and base['Os'] == 'linux' and base['Architecture'] == 'amd64', 'actual_base_identity_mismatch')
        receipt['base'] = {'manifest_digest':lock['base_manifest_digest'],'config_digest':base['Id'],
                           'compressed_bytes':lock['base_compressed_bytes'],'rootfs_layers':base['RootFS']['Layers']}
        containers.append(builder)
        docker('run','--detach','--pull=never','--name',builder,'--cpus=1','--memory=3g','--pids-limit=256',
               '--env','DEBIAN_FRONTEND=noninteractive','--env','LC_ALL=C',image,'sleep','infinity', name='builder-create')
        builder_state = json.loads(docker('inspect',builder,name='builder-boundary'))[0]
        require(builder_state['HostConfig']['Memory'] == 3*1024**3 and builder_state['HostConfig']['NanoCpus'] == 10**9
                and builder_state['HostConfig']['PidsLimit'] == 256, 'builder_runtime_boundary')
        execute('/bin/sh','-ec', 'rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*; rm -rf /var/lib/apt/lists/*; printf %s "$1" > /etc/apt/sources.list.d/trial.sources',
                'sh', SOURCES, name='official-sources')
        execute('apt-get', *APT_OPTIONS, 'update', name='signed-current-update', timeout=300)
        names = execute('/bin/sh','-ec','printf "%s\\n" /var/lib/apt/lists/*_InRelease', name='release-names').decode().splitlines()
        releases = [release_identity(execute('cat', name, name='release-' + str(i)), time.time()) for i,name in enumerate(names)]
        require({r['codename'] for r in releases} == {'trixie','trixie-updates','trixie-security'}, 'complete_signed_sources_required')
        for index, entry in enumerate(lock['packages'].values()):
            package_matches(execute('apt-cache','show',entry['Package']+'='+entry['Version'], name='package-metadata-'+str(index)), entry)
        simulate = execute('apt-get',*APT_OPTIONS,'--simulate','--no-install-recommends','install',*lock['requested'], name='install-simulation')
        require(not re.search(rb'^Remv ',simulate,re.M), 'package_removal_refused')
        simulated_packages = re.findall(rb'^Inst (\S+)(?: \[[^\]]+\])? \((\S+)',simulate,re.M)
        require(simulated_packages and len(simulated_packages) <= 160, 'bounded_simulation_required')
        raw_plan = execute('apt-get',*APT_OPTIONS,'--download-only','--print-uris','--yes','--no-install-recommends','install',*lock['requested'], name='payload-plan')
        plan = download_plan(raw_plan, lock['maximum_package_download_bytes'])
        installed_sizes = execute('apt-cache','show',*[p.decode()+'='+v.decode() for p,v in simulated_packages], name='installed-size-plan')
        base_sizes = execute('dpkg-query','-W','-f=${Installed-Size}\n',name='base-installed-size')
        predicted_size = sum(int(x) for x in base_sizes.splitlines()) + sum(int(x['Installed-Size']) for x in paragraphs(installed_sizes))
        require(predicted_size <= lock['maximum_installed_size_kib'], 'simulated_installed_size_bound')
        write('apt-plan.json', {'signature_and_date_checks':True,'maximum_release_age_s':7776000,'releases':releases,
                               'matched_locked_packages':lock['packages'],'payloads':plan,'download_bytes':sum(x['bytes'] for x in plan),
                               'installed_size_upper_bound_kib':predicted_size,'simulation_sha256':sha(simulate),'current_official_sources':SOURCES})
        execute('apt-get',*APT_OPTIONS,'--download-only','--yes','--no-install-recommends','install',*lock['requested'], name='payload-download', timeout=600)
        sums = execute('sha256sum', *['/var/cache/apt/archives/' + x['filename'] for x in plan], name='downloaded-payload-hashes').decode().splitlines()
        observed = {Path(line.split(None,1)[1].strip()).name:line.split(None,1)[0] for line in sums}
        require(observed == {x['filename']:x['sha256'] for x in plan}, 'downloaded_payload_identity')
        execute('apt-get',*APT_OPTIONS,'--no-download','--yes','--no-install-recommends','install',*lock['requested'], name='offline-package-install', timeout=300)
        execute('/bin/ln','-s','/usr/bin/g++-14','/usr/local/bin/c++', name='fixture-cxx-alias')
        identity = json.loads(execute('python3','-c',IDENTITY, name='installed-identity'))
        versions = {x['package'].split(':')[0]:x['version'] for x in identity['installed_packages']}
        require(all(versions.get(x['Package']) == x['Version'] for x in lock['packages'].values()), 'installed_exact_package_versions')
        actual_sizes = execute('dpkg-query','-W','-f=${Installed-Size}\n', name='actual-installed-sizes')
        require(sum(int(x) for x in actual_sizes.splitlines()) <= lock['maximum_installed_size_kib'], 'actual_installed_size_bound')
        tag = 'geos-680-toolchain:' + suffix
        docker('commit',builder,tag, name='builder-commit')
        built = json.loads(docker('image','inspect',tag, name='builder-inspect'))[0]
        identity['image_id'] = built['Id']; identity['rootfs_layers'] = built['RootFS']['Layers']
        identity['base'] = receipt['base']; identity['builder_script_sha256'] = source['trial_files'][str(Path(__file__).relative_to(ROOT))]
        write('builder-identity.json', identity)
        cache = private/'cache'; cache.mkdir()
        geos_lock = json.loads((ROOT/'takx/native-geos/inputs.lock.json').read_text())
        inputs = [geos_lock['archives']['geos-3.4.3'],geos_lock['source_patch']]
        for item in inputs:
            with urllib.request.urlopen(item['url'], timeout=30) as stream:
                raw = stream.read(item['bytes']+1)
            require(len(raw) == item['bytes'] and sha(raw) == item['sha256'], 'locked_source_download_identity')
            (cache/item['sha256']).write_bytes(raw)
        profile_root = private/'profile'; profile_root.mkdir()
        containers.append(consumer)
        proof = docker('run','--pull=never','--name',consumer,'--network=none','--cpus=1','--memory=3g','--pids-limit=256',
                       '--read-only','--tmpfs','/tmp:rw,size=128m','--workdir','/src',
                       '--volume',str(ROOT)+':/src:ro','--volume',str(cache)+':/cache:ro',
                       '--volume',str(profile_root)+':/proof:rw',built['Id'],'/bin/sh','-ec',
                       'python3 -B takx/native-geos/build.py --output /proof/output --cache /cache --cc /usr/bin/gcc-14 --cxx /usr/bin/g++-14; '
                       'TAKX_NATIVE_GEOS_PROOF=/proof/output python3 -B -m unittest discover -s takx/native-geos -p test_build.py -v', name='fresh-profile-and-tests', timeout=850)
        state = json.loads(docker('inspect',consumer, name='proof-container-inspect'))[0]
        require(state['State']['ExitCode'] == 0 and not state['State']['OOMKilled'] and state['HostConfig']['NetworkMode'] == 'none'
                and state['HostConfig']['Memory'] == 3*1024**3 and state['HostConfig']['NanoCpus'] == 10**9, 'proof_runtime_boundary')
        require(re.search(rb'\nRan 18 tests in [^\n]+\n\nOK\n?$',proof) is not None and b'skipped' not in proof, 'all_18_actual_profile_tests_required')
        complete = json.loads((profile_root/'output/complete.json').read_text())
        require(complete['integer_configuration']['contract'] == 'historical-geos-int64-v1' and complete['geometry_and_error_controls'] is True
                and complete['strict_pic'] is True, 'incomplete_profile_receipt')
        for name in ('jni_acceptance','modern_geos_api_compatibility','security_acceptance','target_image_abi_acceptance','kernel_sdk_acceptance','takx_acceptance'):
            require(complete[name] is False, 'acceptance_scope_changed')
        require(all(sha((ROOT/name).read_bytes()) == expected for name,expected in lock['source_sha256'].items()), 'source_changed_during_trial')
        require(all(sha((ROOT/name).read_bytes()) == expected for name,expected in source['trial_files'].items()), 'trial_changed_during_run')
        write('geos-complete.json', complete)
        receipt.update(status='passed',native_amd64_component_behavior=True,tests={'run':18,'passed':18,'skipped':0},
                       source_downloads=[{k:x[k] for k in ('url','bytes','sha256')} for x in inputs],
                       builder_image_id=built['Id'],profile_output_sha256=sha(proof),profile_network='none',cpus=1,memory_bytes=3*1024**3)
    except Exception as error:
        receipt['reason'] = str(error) if isinstance(error, Rejected) else 'unexpected_' + type(error).__name__
    finally:
        receipt['cleanup'] = []
        for name in reversed(containers):
            try:
                result = subprocess.run(['docker','rm','--force',name],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
                receipt['cleanup'].append({'container':name,'returncode':result.returncode})
                if result.returncode and receipt['status'] == 'passed':
                    receipt.update(status='failed',reason='owned_container_cleanup_failed')
            except subprocess.TimeoutExpired:
                receipt['cleanup'].append({'container':name,'timeout':True})
                receipt.update(status='failed',reason='owned_container_cleanup_timeout')
        receipt['command_results'] = commands
        receipt['elapsed_seconds'] = round(time.monotonic()-started,3)
        if receipt['status'] != 'passed':
            receipt['native_amd64_component_behavior'] = False
            (evidence/'geos-complete.json').unlink(missing_ok=True)
        write('trial-result.json', receipt)
    print('GEOS 680 hosted trial: ' + receipt['status'])
    return 0 if receipt['status'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
