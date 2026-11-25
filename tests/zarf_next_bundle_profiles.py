# Copyright 2026 uds-takserver authors
# SPDX-License-Identifier: GPL-3.0-only

"""Stage the committed slim and Full Core profiles for signed assembly tests."""

import json
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


def stage_profile(source, app, key, destination):
    destination.mkdir()
    (destination / "tak.pub").write_bytes(key.read_bytes())
    packages = yaml.safe_load(source.read_text())["packages"]
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
        if values := package_values(package, source):
            filename = f"{name}.yaml"
            (destination / filename).write_text(yaml.safe_dump(values, sort_keys=False))
            lines.append(f'  values_files = ["{filename}"]')
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


def verify_profiles(root, app, key, work, arch, env):
    for profile, relative in (("slim", "bundle/uds-bundle.yaml"),
                              ("full", "bundle/full/uds-bundle.yaml")):
        destination = work / profile
        names = stage_profile(root / relative, app, key, destination)
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
        archive.unlink()
