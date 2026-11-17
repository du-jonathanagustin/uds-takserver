#!/usr/bin/env python3
# Copyright 2026 uds-takserver authors
# SPDX-License-Identifier: GPL-3.0-only
"""Fork-only execution proof of frozen GEOS inputs; no publisher authority."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
SOURCE = '50de1c9d3a9443a01560b9e951a617adb871d39c'
FORK = 'du-jonathanagustin/uds-takserver'
BRANCH = 'refs/heads/proof/geos-cache-681'
WORKFLOW = '.github/workflows/geos-cache-fork-proof.yaml'
HELPER = '.github/scripts/geos-cache-hosted-proof.py'
IMAGE = 'docker.io/library/gcc@sha256:82549aa8f90ada3236a8be70c74543132a76662ef33f0c3271ed802b81584a82'
CONFIG = 'sha256:b68c134517a27e91bb2568eb4b46073dfb48d9aa740423ec13b0da6442d643fb'
RECIPE = ('takx/geos-cache/cache.py', 'takx/geos-cache/producer.py', 'takx/geos-cache/qualify.py',
          'takx/geos-cache/inputs.lock.json', 'takx/native-geos/GeosGeometry.c',
          'takx/native-geos/build.py', 'takx/native-geos/inputs.lock.json', 'takx/native-geos/patch.json',
          'takx/native-las/build.py', 'takx/native-deps/build.py')
DENIED = ('registry_roundtrip', 'publisher_authenticated', 'sdk_accepted', 'security_accepted')
HOST_ENV = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(Path.home()),
            'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC'}


class Rejected(ValueError):
    pass


def require(value, reason):
    if not value:
        raise Rejected(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def file_sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def pairs(items):
    result = {}
    for name, value in items:
        require(name not in result, 'duplicate_json_key')
        result[name] = value
    return result


def decode(raw):
    require(len(raw) <= 2 * 1024**2, 'metadata_bound')
    return json.loads(raw, object_pairs_hook=pairs)


class Proof:
    def __init__(self, temporary):
        self.base = temporary / 'geos-cache-681-private'
        self.report = temporary / 'geos-cache-681-report'
        self.base.mkdir(mode=0o700)
        self.report.mkdir(mode=0o700)
        self.deadline = time.monotonic() + 3000
        self.phase, self.commands, self.count = 'preflight', [], 0
        self.observed, self.builder = {}, None

    def write(self, name, value):
        raw = json.dumps(value, sort_keys=True, indent=2).encode() + b'\n'
        require(len(raw) <= 2 * 1024**2, 'artifact_bound')
        with (self.report / name).open('xb') as stream:
            stream.write(raw)

    def run(self, command, name, timeout=60, cleanup=False):
        self.count += 1
        log = self.base / (str(self.count) + '-' + name + '.log')
        deadline = time.monotonic() + timeout
        if not cleanup:
            deadline = min(deadline, self.deadline)
        child, complete = None, False
        kind = {'fresh-producer': 'producer', 'two-prefix-consumer': 'consumer'}.get(name)
        next_observation = time.monotonic() + 1
        try:
            with log.open('xb') as stream:
                require(time.monotonic() < deadline, 'command_deadline')
                child = subprocess.Popen(command, cwd=ROOT, env=HOST_ENV, stdin=subprocess.DEVNULL,
                    stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
                while True:
                    require(log.stat().st_size <= 8 * 1024**2, 'command_output_bound')
                    require(time.monotonic() < deadline, 'command_deadline')
                    if child.poll() is not None:
                        complete = True
                        break
                    if kind and kind not in self.observed and time.monotonic() >= next_observation:
                        self.observe(kind)
                        next_observation = time.monotonic() + 2
                    time.sleep(0.2)
            require(child.returncode == 0, 'command_failed')
            require(not kind or kind in self.observed, 'running_container_evidence_missing')
            with log.open('rb') as stream:
                raw = stream.read(8 * 1024**2 + 1)
            require(len(raw) <= 8 * 1024**2, 'command_output_bound')
            return raw
        finally:
            if child is not None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()
            self.commands.append({'phase': name, 'complete': complete,
                'returncode': child.returncode if child is not None else None,
                'bytes': log.stat().st_size if log.exists() else 0,
                'sha256': file_sha(log) if log.exists() else None})

    def observe(self, kind):
        raw = self.run(['docker', 'ps', '-q', '--no-trunc', '--filter', 'name=^uds-geos-'],
                       'resource-list-' + kind, timeout=10)
        ids = raw.decode().split()
        require(len(ids) <= 4 and all(re.fullmatch('[0-9a-f]{64}', item) for item in ids), 'resource_list_bound')
        for index, item in enumerate(ids):
            details = decode(self.run(['docker', 'inspect', item], 'resource-inspect-' + kind + '-' + str(index),
                                     timeout=10))[0]
            mounts = [m for m in details.get('Mounts', []) if m.get('Destination') == '/build']
            if not (re.fullmatch('uds-geos-[0-9a-f]{32}', details['Name'].lstrip('/'))
                    and details['Image'] == CONFIG and len(mounts) == 1
                    and mounts[0].get('Source') == str(self.base / kind)):
                continue
            config = details['HostConfig']
            binds = {m['Destination']: m for m in details['Mounts'] if m.get('Type') == 'bind'}
            require(set(binds) == {'/repo', '/build', '/inputs'} and binds['/repo']['Source'] == str(ROOT)
                    and binds['/repo']['RW'] is False and binds['/inputs']['RW'] is False
                    and binds['/build']['RW'] is True, 'actual_bind_mount_mismatch')
            if kind == 'producer':
                require(binds['/inputs']['Source'] == str(self.base / 'sources'), 'producer_input_mount_mismatch')
            else:
                stage = Path(binds['/inputs']['Source'])
                require(stage.parent == Path('/tmp') and stage.name.startswith('geos-consumer-inputs-')
                        and set(p.name for p in stage.iterdir()) == {'oci', 'request.json'},
                        'consumer_input_projection_mismatch')
            require(config['NanoCpus'] == 1000000000 and config['Memory'] == 3 * 1024**3
                    and config['PidsLimit'] == 256 and config['ReadonlyRootfs'] is True
                    and config['NetworkMode'] == 'none' and config['Privileged'] is False
                    and 'ALL' in config['CapDrop']
                    and any(v.split(':', 1)[0] == 'no-new-privileges' for v in config['SecurityOpt']),
                    'actual_container_constraint_mismatch')
            cgroup = decode(self.run(['docker', 'exec', item, '/usr/bin/python3', '-c',
                'import json,pathlib; print(json.dumps({n:(pathlib.Path("/sys/fs/cgroup")/n).read_text().strip() '
                'for n in ("cpu.max","memory.max","pids.max")}))'], 'resource-cgroup-' + kind, timeout=10))
            cpu = cgroup['cpu.max'].split()
            require(len(cpu) == 2 and cpu[0].isdigit() and cpu[1].isdigit()
                    and int(cpu[0]) == int(cpu[1]) > 0 and cgroup['memory.max'] == str(3 * 1024**3)
                    and cgroup['pids.max'] == '256', 'actual_cgroup_constraint_mismatch')
            self.observed[kind] = {'container_id': item, 'image_config': details['Image'],
                'host_config': {k: config[k] for k in ('NanoCpus', 'Memory', 'PidsLimit', 'ReadonlyRootfs',
                    'NetworkMode', 'Privileged', 'CapDrop', 'SecurityOpt')}, 'cgroup_v2': cgroup,
                'bind_mounts': {destination: {'read_only': not value['RW']} for destination, value in binds.items()},
                'inputs_projection': 'exact_source_archives' if kind == 'producer' else 'verified_local_oci_only'}
            return

    def source(self):
        expected = {name: sha(self.run(['git', 'show', SOURCE + ':' + name], 'pinned-source-' + str(i)))
                    for i, name in enumerate(RECIPE)}
        actual = {name: file_sha(ROOT / name) for name in RECIPE}
        require(actual == expected, 'consumed_source_mismatch')
        return expected

    def cleanup(self):
        """Only new profile containers whose writable mount is this proof's output."""
        raw = self.run(['docker', 'ps', '-aq', '--no-trunc', '--filter', 'name=^uds-geos-'],
                       'owned-container-list', timeout=15, cleanup=True)
        ids = raw.decode().split()
        require(len(ids) <= 4 and all(re.fullmatch('[0-9a-f]{64}', item) for item in ids), 'cleanup_list_bound')
        for index, item in enumerate(ids):
            details = decode(self.run(['docker', 'inspect', item], 'owned-container-inspect-' + str(index),
                                     timeout=15, cleanup=True))[0]
            mounts = [m for m in details.get('Mounts', []) if m.get('Destination') == '/build']
            owned = (re.fullmatch('uds-geos-[0-9a-f]{32}', details['Name'].lstrip('/'))
                     and details['Image'] == CONFIG and len(mounts) == 1
                     and mounts[0].get('Source') in (str(self.base / 'producer'), str(self.base / 'consumer')))
            if owned:
                self.run(['docker', 'rm', '-f', item], 'owned-container-remove-' + str(index),
                         timeout=15, cleanup=True)


def container_evidence(base):
    statuses, failure, seen = [], None, 0
    for relative in ('producer', 'consumer'):
        paths = []
        for path in (base / relative).glob('*.status.json'):
            if seen >= 256:
                failure = failure or 'command_status_bound'
                break
            seen += 1
            if len(path.name) > 128 or not re.fullmatch('[0-9]+-[a-z0-9+-]+[.]status[.]json', path.name):
                failure = failure or 'unexpected_command_status'
                continue
            paths.append(path)
        for path in sorted(paths):
            try:
                require(not path.is_symlink() and path.is_file(), 'ordinary_status_required')
                with path.open('rb') as stream:
                    status = decode(stream.read(2 * 1024**2 + 1))
                require(set(status) == {'complete', 'returncode', 'bytes', 'sha256'}, 'status_schema')
                require(type(status['complete']) is bool and
                        (status['returncode'] is None or type(status['returncode']) is int)
                        and type(status['bytes']) is int and 0 <= status['bytes'] <= 1024**3
                        and type(status['sha256']) is str and re.fullmatch('[0-9a-f]{64}', status['sha256']),
                        'status_scalar_schema')
                log = path.with_suffix('').with_suffix('.log')
                require(log.stat().st_size == status['bytes'] and file_sha(log) == status['sha256'], 'status_digest')
                statuses.append({'directory': relative, 'name': path.name, **status})
            except Exception:
                failure = failure or 'incomplete_status_evidence'
    return statuses, failure


def main():
    os.umask(0o077)
    proof, result, failure = None, None, None
    try:
        require(os.environ.get('GITHUB_EVENT_NAME') == 'push' and os.environ.get('GITHUB_REPOSITORY') == FORK
                and os.environ.get('GITHUB_REF') == BRANCH, 'fork_push_only')
        require(platform.system() == 'Linux' and platform.machine() == 'x86_64'
                and os.environ.get('RUNNER_ARCH') == 'X64', 'native_linux_amd64_only')
        temporary = Path(os.environ['RUNNER_TEMP']).resolve()
        require(not temporary.is_relative_to(ROOT), 'external_runner_temporary_required')
        proof = Proof(temporary)
        head = proof.run(['git', 'rev-parse', 'HEAD'], 'checkout-source').decode().strip()
        require(re.fullmatch('[0-9a-f]{40}', head) and head == os.environ['GITHUB_SHA']
                and head == os.environ['PROOF_WORKFLOW_SHA']
                and os.environ['PROOF_WORKFLOW_REF'] == FORK + '/' + WORKFLOW + '@' + BRANCH,
                'workflow_checkout_identity_mismatch')
        require(proof.run(['git', 'rev-parse', 'HEAD^'], 'proof-parent').decode().strip() == SOURCE,
                'proof_parent_must_be_frozen_source')
        changed = set(proof.run(['git', 'diff', '--name-only', SOURCE, head], 'proof-only-files').decode().splitlines())
        require(changed == {WORKFLOW, HELPER}, 'unrelated_proof_change')
        source = proof.source()
        test_path = 'takx/geos-cache/test_cache.py'
        test_sha256 = sha(proof.run(['git', 'show', SOURCE + ':' + test_path], 'pinned-test-source'))
        require(file_sha(ROOT / test_path) == test_sha256, 'validation_source_mismatch')
        proof_recipe = {name: file_sha(ROOT / name) for name in (WORKFLOW, HELPER)}
        proof.write('source.json', {'schema': 'uds-geos-fork-source-v1', 'component_source_commit': SOURCE,
            'checkout_sha': head, 'workflow_ref': os.environ['PROOF_WORKFLOW_REF'], 'workflow_sha': head,
            'workflow_sha256': file_sha(ROOT / WORKFLOW), 'helper_sha256': file_sha(ROOT / HELPER),
            'consumed_recipe_sha256': source, 'repository': FORK,
            'offline_test_sha256': test_sha256,
            'run_id': os.environ['GITHUB_RUN_ID'], 'run_attempt': os.environ['GITHUB_RUN_ATTEMPT']})
        sys.path.insert(0, str(ROOT / 'takx/geos-cache'))
        import cache
        import producer
        require(producer.RECIPE == RECIPE and producer.LOCK['base_image']['reference'] == IMAGE
                and producer.LOCK['base_image']['config'] == CONFIG, 'component_contract_mismatch')
        proof.phase = 'offline_guards'
        guards = proof.run([sys.executable, '-B', '-m', 'unittest', 'discover', '-s', 'takx/geos-cache',
                           '-p', 'test_*.py', '-v'], 'fifteen-offline-guards', timeout=90)
        require(re.search(rb'\nRan 15 tests in [0-9.]+s\n\nOK\n', guards), 'fifteen_unskipped_guards_required')
        proof.phase = 'builder_identity'
        server = decode(proof.run(['docker', 'version', '--format', '{{json .Server}}'], 'docker-server-version'))
        info = decode(proof.run(['docker', 'info', '--format', 'json'], 'docker-server-info'))
        require(info['OSType'] == 'linux' and info['Architecture'] in ('x86_64', 'amd64')
                and server['Os'] == 'linux' and server['Arch'] == 'amd64'
                and info['CgroupVersion'] == '2', 'native_docker_server_required')
        require(shutil.disk_usage(temporary).free >= 6 * 1024**3, 'builder_free_space_below_6GiB')
        binaries = {}
        for name, command in (('python3', [sys.executable, '--version']), ('git', ['git', '--version']),
                              ('docker', ['docker', '--version']), ('dockerd', ['dockerd', '--version'])):
            path = Path(sys.executable if name == 'python3' else shutil.which(name)).resolve()
            binaries[name] = {'path': str(path), 'sha256': file_sha(path),
                              'version': proof.run(command, 'host-' + name).decode().strip()}
        auth = proof.base / 'anonymous-docker'; auth.mkdir()
        (auth / 'config.json').write_text('{"auths":{}}\n')
        proof.phase = 'pinned_image_pull'
        proof.run(['docker', '--config', str(auth), 'pull', '--platform', 'linux/amd64', IMAGE],
                  'anonymous-pinned-image-pull', timeout=300)
        image = decode(proof.run(['docker', 'image', 'inspect', IMAGE], 'pinned-image-readback'))[0]
        require(image['Id'] == CONFIG and image['Architecture'] == 'amd64' and image['Os'] == 'linux'
                and any(value.endswith('@' + IMAGE.rsplit('@', 1)[1]) for value in image['RepoDigests']),
                'pinned_image_readback_mismatch')
        proof.builder = {'schema': 'uds-geos-fork-builder-v1', 'system': platform.system(),
            'machine': platform.machine(), 'kernel_release': platform.release(), 'host_binaries': binaries,
            'docker_server': {k: server[k] for k in ('Version', 'ApiVersion', 'GitCommit', 'Os', 'Arch', 'KernelVersion')},
            'storage_driver': info['Driver'], 'runner_image_os': os.environ.get('ImageOS'),
            'runner_image_version': os.environ.get('ImageVersion'),
            'image': IMAGE, 'image_config': image['Id'], 'image_native_arch': image['Architecture'],
            'image_rootfs_diff_ids': image['RootFS']['Layers'], 'requested_constraints': producer.LOCK['constraints']}
        proof.phase = 'fresh_source_build'
        output = proof.base / 'producer'
        proof.run([sys.executable, '-B', 'takx/geos-cache/producer.py', '--engine', 'docker',
            '--output', str(output), '--source-cache', str(proof.base / 'sources')], 'fresh-producer', timeout=2300)
        result = cache.decode(cache.read(output / 'result.json'))
        require(result['schema'] == 'uds-geos-capi-fresh-local-v1' and result['identity']['recipes'] == source
                and all(result[key] is False for key in DENIED)
                and result['identity']['execution'] == {'engine_host_arch': 'amd64', 'container_machine': 'x86_64',
                    'mode': 'native', 'target_os': 'linux', 'target_arch': 'amd64'}, 'fresh_result_identity_mismatch')
        manifest, _ = cache.verify_layout(output / 'oci', result['local_oci_subject'], result['input_key'])
        require(manifest['identity'] == result['identity'] and manifest['qualification'] == result['qualification']
                and cache.file_sha(output / 'geos-capi.tar.gz') == result['capsule_sha256'], 'local_oci_result_mismatch')
        proof.write('producer-result.json', result)
        proof.phase = 'two_prefix_execution'
        consumer = proof.base / 'consumer'
        proof.run([sys.executable, '-B', 'takx/geos-cache/qualify.py', '--engine', 'docker',
            '--layout', str(output / 'oci'), '--subject', result['local_oci_subject'],
            '--input-key', result['input_key'], '--output', str(consumer)], 'two-prefix-consumer', timeout=720)
        restored = cache.decode(cache.read(consumer / 'restored.json'))
        require(restored['schema'] == 'uds-geos-capi-local-relocation-v1'
                and restored['subject'] == result['local_oci_subject'] and restored['input_key'] == result['input_key']
                and restored['identity_sha256'] == cache.sha(cache.canonical(result['identity']))
                and restored['execution'] == result['identity']['execution']
                and restored['constraints'] == result['identity']['constraints']
                and restored['original_producer_available'] is False and restored['host_geos_available'] is False
                and all(restored[key] is False for key in DENIED)
                and [row['prefix'] for row in restored['results']] == ['first', 'unrelated/deeper/second']
                and all(row['geometry'] is True and row['whole_archive_pic'] is True
                        and row['runtime_providers'] == result['qualification']['runtime_providers']
                        and row['pic_runtime_providers'] == row['runtime_providers'] for row in restored['results']),
                'two_prefix_result_mismatch')
        proof.write('restored.json', restored)
        proof.phase = 'final_source_lease'
        require(proof.source() == source and file_sha(ROOT / test_path) == test_sha256
                and {name: file_sha(ROOT / name) for name in (WORKFLOW, HELPER)} == proof_recipe
                and proof.run(['git', 'rev-parse', 'HEAD'], 'final-checkout-source').decode().strip() == head,
                'final_consumed_source_drift')
        require(all(file_sha(Path(value['path'])) == value['sha256'] for value in binaries.values()),
                'host_tool_drift')
        final_image = decode(proof.run(['docker', 'image', 'inspect', IMAGE], 'final-image-readback'))[0]
        require(all(final_image[name] == image[name] for name in ('Id', 'Architecture', 'Os', 'RootFS')),
                'builder_image_drift')
        cache.verify_layout(output / 'oci', result['local_oci_subject'], result['input_key'])
        proof.phase = 'complete'
    except Rejected as error:
        failure = str(error)
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, OSError, RuntimeError, subprocess.SubprocessError):
        failure = 'unavailable_or_invalid_proof_input'
    finally:
        if proof:
            try:
                proof.cleanup()
            except Exception:
                if failure is None:
                    failure = 'owned_cleanup_unavailable'
            statuses, status_failure = container_evidence(proof.base)
            failure = failure or status_failure
            if proof.phase == 'complete' and not (
                    {row['directory'] for row in statuses} == {'producer', 'consumer'}
                    and all(row['complete'] is True and row['returncode'] == 0 for row in statuses)):
                failure = failure or 'incomplete_success_command_evidence'
            if proof.builder is not None:
                proof.write('builder.json', {**proof.builder, 'observed_container_resources': proof.observed})
            proof.write('command-evidence.json', {'schema': 'uds-geos-fork-command-evidence-v1',
                'host_commands': proof.commands, 'container_commands': statuses, 'raw_logs_included': False})
            proof.write('outcome.json', {'schema': 'uds-geos-fork-outcome-v1', 'component_source_commit': SOURCE,
                'workflow_commit': os.environ.get('GITHUB_SHA'), 'phase': proof.phase, 'failure': failure,
                'fresh_source_build': proof.phase == 'complete' and failure is None,
                'two_prefix_execution': proof.phase == 'complete' and failure is None,
                'upstream_required_check': False, 'protected_publisher_qualification': False,
                **{key: False for key in DENIED}})
    if failure:
        print('GEOS fork proof failed: ' + failure, file=sys.stderr)
        return 1
    print('GEOS fork proof complete: native component build and two-prefix controls; registry/SDK gates remain open')
    return 0


if __name__ == '__main__':
    sys.exit(main())
