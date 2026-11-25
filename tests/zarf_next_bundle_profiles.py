# Copyright 2026 uds-takserver authors
# SPDX-License-Identifier: GPL-3.0-only

"""Stage the committed slim and Full Core profiles for signed assembly tests."""

import json
import os
import subprocess

import yaml


def package_values(package, source):
    values = {}
    for component, charts in package.get("overrides", {}).items():
        for chart, override in charts.items():
            if unknown := override.keys() - {"valuesFiles", "values", "variables"}:
                raise ValueError(f"Unmapped chart override fields: {sorted(unknown)}")
            chart_values = values.setdefault(component, {}).setdefault(chart, {})
            for name in override.get("valuesFiles", []):
                chart_values.update(yaml.safe_load((source.parent / name).read_text()))
            for entry in override.get("values", []):
                *parents, field = entry["path"].split(".")
                target = chart_values
                for parent in parents:
                    target = target.setdefault(parent, {})
                target[field] = entry["value"]
    if package["name"] != "takserver":
        return values

    legacy = yaml.safe_load(source.with_name("uds-config.yaml").read_text())["variables"]["takserver"]
    paths = {
        "DOMAIN": ("global", "domain"),
        "TAK_IMAGE_TAG": ("tak", "imageTag"),
        "FILESYSTEM_BACKUP": ("backup", "filesystem", "enabled"),
        "POSTGRES_STORAGE_CLASS": ("storage", "postgresClass"),
        "CLOUDTAK_STORAGE_CLASS": ("storage", "cloudtakClass"),
    }
    overrides = {"chartOverrides": values}
    for name, value in legacy.items():
        if name not in paths:
            raise ValueError(f"Unmapped profile variable: {name}")
        *parents, field = paths[name]
        target = overrides
        for parent in parents:
            target = target.setdefault(parent, {})
        target[field] = value
    return overrides



def runtime_overlay(package):
    names = {
        entry["name"]
        for charts in package.get("overrides", {}).values()
        for override in charts.values()
        for entry in override.get("variables", [])
    }
    if package["name"] == "takserver":
        if names - {"CLOUDTAK_BASEMAP_ENABLED", "CLOUDTAK_SSO_GROUPS"}:
            raise ValueError(f"Unmapped TAK chart variables: {sorted(names)}")
        if not names:
            return ""
        supports_basemap = "true" if "CLOUDTAK_BASEMAP_ENABLED" in names else "false"
        return """{{- $basemap := index .vars "CLOUDTAK_BASEMAP_ENABLED" }}
{{- $groups := index .vars "CLOUDTAK_SSO_GROUPS" }}
{{- $setBasemap := and SUPPORTS_BASEMAP (ne $basemap nil) }}
{{- if or $setBasemap (ne $groups nil) }}
chartOverrides:
  cloudtak:
    uds-cloudtak:
      {{- if $setBasemap }}
      basemap:
        enabled: {{ $basemap }}
      {{- end }}
      {{- if ne $groups nil }}
      sso:
        groups: [{{ range $i, $group := $groups }}{{ if $i }}, {{ end }}{{ printf "%q" $group }}{{ end }}]
      {{- end }}
{{- else }}
{}
{{- end }}
""".replace("SUPPORTS_BASEMAP", supports_basemap)
    if not names:
        return ""
    if names != {"TENANT_TLS_CERT", "TENANT_TLS_KEY"}:
        raise ValueError(f"Unmapped Core chart variables: {sorted(names)}")
    return """{{- $cert := index .vars "TENANT_TLS_CERT" }}
{{- $key := index .vars "TENANT_TLS_KEY" }}
{{- if or $cert $key }}
istio-tenant-gateway:
  uds-istio-config:
    tls:
      {{- with $cert }}
      cert: {{ printf "%q" . }}
      {{- end }}
      {{- with $key }}
      key: {{ printf "%q" . }}
      {{- end }}
{{- else }}
{}
{{- end }}
"""


def stage_profile(source, app, key, destination):
    destination.mkdir()
    (destination / "tak.pub").write_bytes(key.read_bytes())
    packages = yaml.safe_load(source.read_text())["packages"]
    # A default config keeps the values templater active even for deployments
    # with no optional variables. No deployment credentials enter the archive.
    (destination / "defaults.uds.hcl").write_text('variables = { DOMAIN = "uds.dev" }\n')
    lines = [
        'uds { bundle_api_version = "uds.dev/v1alpha1" }',
        'metadata {',
        '  name = "tak-profile-qualification"',
        '  version = "0.1.0"',
        '}',
    ]
    names = []
    for package in packages:
        name = package["name"]
        location = (f'oci://{package["repository"]}:{package["ref"]}'
                    if "repository" in package else str(app.resolve()))
        lines.extend([f'package {json.dumps(name)} {{', f'  source = {json.dumps(location)}'])
        if names:
            lines.append(f'  depends_on = [package.{names[-1]}]')
        names.append(name)
        if optional := package.get("optionalComponents"):
            lines.append(f'  optional_components = {json.dumps(optional)}')
        values_files = []
        if values := package_values(package, source):
            filename = f"{name}.yaml"
            (destination / filename).write_text(yaml.safe_dump(values, sort_keys=False))
            values_files.append(filename)
        if overlay := runtime_overlay(package):
            filename = f"{name}-runtime.yaml"
            (destination / filename).write_text(overlay)
            values_files.append(filename)
        if values_files:
            lines.append(f"  values_files = {json.dumps(values_files)}")
        if "repository" in package:
            signer = package["keylessVerification"]
            identity = json.dumps(signer["certificateIdentityRegexp"])
            issuer = json.dumps(signer["certificateOIDCIssuer"])
            lines.extend([
                '  signature_verification {',
                '    keyless {',
                f'      certificate_identity_regexp = {identity}',
                f'      certificate_oidc_issuer = {issuer}',
                '    }',
                '  }',
            ])
        else:
            if name != "takserver":
                raise ValueError(f"Unexpected local package: {name}")
            lines.append('  signature_verification { public_key = file("tak.pub") }')
        lines.append("}")
    (destination / "bundle.uds.hcl").write_text("\n".join(lines) + "\n")
    return names


def test_full_core(root, source, archive, key, env):
    core = yaml.safe_load(source.read_text())["packages"][0]
    if core["name"] != "core-base" or not core["ref"].endswith("-upstream"):
        raise ValueError("Expected a published Core Base checkpoint")
    runtime_env = {
        **os.environ,
        "SLIM_CORE_VERSION": core["ref"].removesuffix("-upstream"),
    }
    subprocess.run(["bash", ".github/scripts/deploy-slim-core.sh"],
                   cwd=root, env=runtime_env, check=True)
    subprocess.run(["uds", "run", "fit-runner", "--no-progress"], cwd=root, check=True)
    subprocess.run(["bash", "tests/local-path-local.sh"], cwd=root, check=True)
    subprocess.run(["uds", "bundle", "deploy", str(archive), "--public-key", str(key)],
                   cwd=root, env=env, check=True)
    subprocess.run(["uds", "run", "setup:keycloak-user", "--with", "group=/UDS Core/Admin",
                    "--no-progress"], cwd=root, check=True)
    for fixture in ("ensure-tak-group", "ensure-outsider", "ensure-map-user"):
        subprocess.run(["python3", f"tests/{fixture}.py"], cwd=root, check=True)
    subprocess.run(["uds", "run", "test:all", "--no-progress"], cwd=root, check=True)
    subprocess.run(["uds", "run", "test:full-core", "--no-progress"], cwd=root, check=True)


def verify_profiles(root, app, key, work, arch, env, *, live_full_core=False):
    for profile, relative in (("slim", "bundle/uds-bundle.yaml"),
                              ("full", "bundle/full/uds-bundle.yaml")):
        destination = work / profile
        source = root / relative
        names = stage_profile(source, app, key, destination)
        subprocess.run(["uds", "bundle", "create", str(destination), "--architecture", arch,
                        "--signing-key", str(work / "cosign.key")], check=True, env=env)
        archive, = destination.glob("uds-bundle-*.tar.zst")
        info = json.loads(subprocess.check_output(
            ["uds", "bundle", "inspect", str(archive), "--public-key", str(key), "--output", "json"],
            env=env,
        ))
        if (info["bundleSignature"]["status"] != "verified"
                or [package["name"] for package in info["packages"]] != names
                or any(package["signature"]["verification"] != "verified" for package in info["packages"])):
            raise ValueError(f"{profile} bundle signature or package inventory differs from source")
        print(f"Verified signed {arch} {profile} bundle with {len(names)} original package IDs", flush=True)
        if profile == "full" and live_full_core:
            test_full_core(root, source, archive, key, env)
        archive.unlink()
