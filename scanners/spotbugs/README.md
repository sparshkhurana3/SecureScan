# SpotBugs with Find Security Bugs (self-built scanner image)

Neither SpotBugs nor Find Security Bugs publishes a container image, so SecureScan builds one from pinned, checksum-verified
releases (design: "Scanner catalogue"). The `Dockerfile` refuses to build unless both SHA-256 values are given.

| Component | Version | Source | Licence |
| --- | --- | --- | --- |
| SpotBugs | 4.10.4 | `https://github.com/spotbugs/spotbugs/releases/download/4.10.4/spotbugs-4.10.4.zip` | LGPL-2.1 |
| Find Security Bugs plugin | 1.14.0 | `https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/1.14.0/findsecbugs-plugin-1.14.0.jar` | LGPL-3.0 |
| Base image | `eclipse-temurin:21-jre` (pin the digest in `deploy/images.lock.yaml`) | Docker Hub | GPL-2.0 with Classpath Exception |

## How to fill the checksums

Never copy a checksum from the same download you are verifying. Take it from the publisher and compare at least two sources.

**SpotBugs zip.**

1. Open the release page `https://github.com/spotbugs/spotbugs/releases/tag/4.10.4`. GitHub shows a `sha256:...` digest next to
   every release asset; the same value is returned by the API field `assets[].digest`:
   `curl -fsS https://api.github.com/repos/spotbugs/spotbugs/releases/tags/4.10.4 | python3 -c "import json,sys;[print(a['name'],a.get('digest')) for a in json.load(sys.stdin)['assets']]"`.
2. Download the zip and its signature `spotbugs-4.10.4.zip.asc` and, if you have the SpotBugs release key, check
   `gpg --verify spotbugs-4.10.4.zip.asc spotbugs-4.10.4.zip`; then `sha256sum spotbugs-4.10.4.zip` must equal the digest.

**Find Security Bugs jar.**

1. Maven Central publishes `.sha1` and `.md5` (and a `.asc` signature) next to the jar, not `.sha256`. Compare
   `https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/1.14.0/findsecbugs-plugin-1.14.0.jar.sha1`
   with `sha1sum findsecbugs-plugin-1.14.0.jar`, verify the `.asc` with GPG if possible, and only then take
   `sha256sum findsecbugs-plugin-1.14.0.jar` as the value to pin.

Pass the values as build arguments, or export them and use the helper:

```
export SPOTBUGS_SHA256=<value>
export FSB_SHA256=<value>
sh spikes/s7/build_spotbugs.sh
```

### Values observed while writing this directory (2026-10-07): confirm them yourself before pinning

They were computed by downloading over HTTPS on a development machine. The SpotBugs value equals the digest GitHub lists for the
asset; the Find Security Bugs jar's SHA-1 equalled the `.sha1` file on Maven Central. They are listed to save time, not as a
substitute for the steps above.

```
SPOTBUGS_SHA256=771c8702beb2b4b6aa20df87ea85f22fda7280c7ce36fce4077b7b3c076d1e14   # spotbugs-4.10.4.zip
FSB_SHA256=6fa340344fa433ff46c2985dab1010e8bc739f9395c983594a5240095e92abc8        # findsecbugs-plugin-1.14.0.jar (sha1 6cc9a0bbd3d1ff0920a1113bbcf0ed3782c91d23)
```

## Bumping a version

1. Change the `SPOTBUGS_VERSION` / `FSB_VERSION` build arguments (or the defaults in the `Dockerfile`) and fill both checksums as above.
2. Rebuild, tag `securescan/spotbugs-fsb:<spotbugs>-<fsb>`, update `deploy/images.lock.yaml` (`SPOTBUGS_FSB`).
3. Run the regression suite (`scanners/regression/`) against `java-planted`; refresh `backend/tests/fixtures/reports/spotbugs.xml`.

## Notes

- The image runs as uid 1000 and should need no writable path except the mounted `/out` and a tmpfs `/tmp` (S7 checks with `docker diff`).
- SpotBugs analyses compiled classes: pass JARs or class directories under the read-only `/src` mount. Never pass user input on
  the command line; M8's command builder takes paths only from the discovery step.
- `-xml:withMessages=<file>` is the plan's output form. If the pinned SpotBugs rejects the `=<file>` suffix, use
  `-xml:withMessages -output /out/spotbugs.xml`; S7's `run_all.sh` tries both and records which one works.
