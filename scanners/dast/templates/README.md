# DAST templates

Fragments the ZAP and Nuclei builders read (`backend/securescan/runner/tools/zap.py`, `nuclei.py`).

- `auth-form.yaml`, `auth-json.yaml`, `auth-browser.yaml`, `auth-header.yaml`: the authentication part of a ZAP plan
  for each login method. `auth-verify.yaml` is the check that the login worked.
- `resolvers.txt`: Nuclei's resolver list (`-r`), copied into the job's `/config`. `127.0.0.11` is Docker's embedded
  DNS, the only resolver a scanner on the internal `dast` network can reach. All real traffic goes through the job's
  proxy, which resolves names itself. Replace it only if Nuclei needs a corporate resolver that the `dast` network can
  reach.

The ZAP plan skeletons themselves are in `scanners/profiles/zap-*.yaml`.
