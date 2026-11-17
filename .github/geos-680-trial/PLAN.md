# Fork-only historical GEOS #680 trial

This branch is an ephemeral proof vehicle for exact source commit
`7de0765783b130e202fa57067692c8a00ed42b6f`. It does not modify PR #682 or any
protected publisher. Root review is required before this branch is pushed.

The workflow triggers only on pushes to `proof/historical-geos-680` in
`du-jonathanagustin/uds-takserver`, on native `ubuntu-24.04` AMD64. Permissions
are `contents: read`; checkout does not persist credentials. No secret,
package write, signing, cluster or other architecture is used. The helper
records all four #682 implementation files and six unchanged recipe/helper
files against fixed SHA-256 values from `7de0765`; it also hashes every trial
file and this workflow against the actual hosted checkout, and rechecks them
before accepting the result.

The public base is official `docker.io/library/debian` native manifest
`sha256:7378260c0a098d27ac206225db5e7d92b8c7c84ea7afccc86eeb513756bbd392`,
config `sha256:596c6d80c879dc94eae22cb9c59a5e18f66f4f9722e170892324c282b4eb19bc`.
Its one compressed layer is 29,856,132 bytes (28.5 MiB), established by the
retained metadata-only preflight. Docker must load that exact config on an
actual AMD64 daemon. Its pull uses a new empty Docker credential configuration.

An owned 1 CPU / 3 GiB / 256 PID container uses only current official Debian
trixie, trixie-updates and trixie-security sources, explicitly Signed-By the
base image's Debian archive keyring. Existing index lists are deleted first.
APT rejects signature/date/Valid-Until failures and any failed update source;
an additional 90-day maximum Release age bounds the stable main Release,
which legitimately lacks Valid-Until. No snapshot, unauthenticated mode,
signature bypass, date bypass, expiry bypass or downgrade option is enabled.
Current signed package records must match the 13 retained tool/package
identities in `lock.json`, including GCC/G++ 14.2.0-19, Make 4.4.1-2 and
binutils 2.44-3. Simulation and print-URIs run before any package payload is
downloaded. Every dependency URI must be an official Debian pool URI with a
SHA-256; download totals must stay at or below 160 MiB and the conservative
base-plus-new-package installed-size estimate at or below 700 MiB. Both are
measured on the runner and fail closed before download. The 13 locked package
records total 51,953,728 compressed bytes (49.5 MiB); some may already belong
to the base, and additional dependencies must fit within the measured 160 MiB
cap. There is no asserted total before that native APT simulation. Every actual downloaded package is
hash-checked before an installation with `--no-download`.

The helper records all installed package versions, Debian keyring and dpkg
status hashes, the real compiler/binutils/Make/Python/patch/ldd binary paths
and hashes and GCC helper binary identities. Actual required versions must
pass before committing an owned local image. The resulting immutable local
image ID and rootfs layers are recorded. The image is never pushed. The only
compatibility alias is `/usr/local/bin/c++ -> /usr/bin/g++-14` for executable
fixture tests; its resolved binary is qualified too.

Only the locked GEOS archive (1,902,752 bytes) and original patch (1,865 bytes)
are downloaded afterward, with exact URL/size/hash checks. A separate owned
container runs the unchanged historical profile from read-only source with a
read-only verified source cache, a new output, read-only root filesystem,
128 MiB temporary filesystem, **no network**, 1 CPU, 3 GiB and 256 PIDs. Its
existing 600-second profile deadline, one-job make and existing disk checks
are preserved. Then all 18 profile tests, including the actual fresh proof,
must pass with zero skips. Actual Docker limits, network mode, exit status and
OOM status are checked. Both owned containers are removed on success or
failure; no shared image/resource cleanup occurs.

The workflow budget is 40 minutes; the helper has a 35-minute command budget
plus bounded cleanup. Package download has a 10-minute bound, source/profile
and tests 850 seconds, other phases 2–5 minutes each within that total.
Raw command logs are limited to 16 MiB each and remain in the runner's private
working directory. Artifacts include only bounded JSON source/base/APT/tool
identities, the genuine producer completion receipt after all controls pass,
and a fixed-reason trial outcome. No raw configure, compiler, package or
unittest log is uploaded. Metadata files are limited to 8 MiB each and retained
for seven days. A failed trial remains failed and retains no successful
component result claim.

This can establish native hosted AMD64 component behavior. It does not satisfy
upstream protected checks, authenticate an image publisher, qualify an SDK or
target image, establish security suitability, or imply performance acceptance.
