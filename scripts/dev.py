#!/usr/bin/env python3
"""Developer entry point for SecureScan. See docs/implementation-plan.md section 2.3.

Only the standard library is needed, except ``pin-images`` (PyYAML, see scripts/pin_images.py).
Compose is always run as:
  docker compose --project-directory deploy --env-file deploy/.env --env-file deploy/images.env \
      -f deploy/compose.yaml [-f deploy/compose.dev.yaml] ...
"""

from __future__ import annotations

import argparse
import os
import secrets as pysecrets
import shutil
import subprocess
import sys
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy"
SECRETS = DEPLOY / "secrets"
TLS = SECRETS / "tls"

# name -> number of random bytes (hex encoded), or None for an empty placeholder
GENERATED_SECRETS: dict[str, int | None] = {
    "postgres_superuser_password": 24,
    "securescan_db_password": 24,
    "defectdojo_db_password": 24,
    "sonarqube_db_password": 24,
    "securescan_master_key": 32,
    "dd_admin_password": 24,
    "dd_secret_key": 32,
    "dd_credential_aes_256_key": 16,  # 32 hex characters: DefectDojo wants a 32-character AES-256 key
    "sonarqube_admin_password": 24,
    "oidc_client_secret": None,
}

# Networks that only on-demand containers join. Compose does not create a network no service uses, so they are
# declared `external` in compose.yaml and created here (name, internal).
ON_DEMAND_NETWORKS: list[tuple[str, bool]] = [
    ("securescan_sonarqube", True),  # SonarQube server and its scanner: no route out
    ("securescan_dast", True),  # DAST scanners and the target-facing proxy: no route out
    ("securescan_egress", False),  # the shared squid proxy's way to the internet
]

TLS_HOSTS = [
    "securescan.localtest.me",
    "dojo.securescan.localtest.me",
    "localhost",
    "db",
    "api",
    "gateway",
]


def run(cmd: list[str], **kwargs: object) -> int:
    print("+", " ".join(cmd))
    return subprocess.run(cmd, **kwargs).returncode  # type: ignore[call-overload]  # noqa: S603


def compose_base(profiles: list[str] | None = None) -> list[str]:
    env_file = DEPLOY / ".env"
    if not env_file.exists():
        shutil.copy(DEPLOY / ".env.example", env_file)
        print(f"created {env_file.relative_to(ROOT)} from .env.example")
    cmd = ["docker", "compose", "--project-directory", str(DEPLOY), "--env-file", str(env_file)]
    images_env = DEPLOY / "images.env"
    if images_env.exists():
        cmd += ["--env-file", str(images_env)]
    cmd += ["-f", str(DEPLOY / "compose.yaml")]
    dev = DEPLOY / "compose.dev.yaml"
    if dev.exists() and profiles and "dev" in profiles:
        cmd += ["-f", str(dev)]
    test = DEPLOY / "compose.test.yaml"
    if test.exists() and profiles and "test" in profiles:
        cmd += ["-f", str(test)]
    for profile in profiles or []:
        cmd += ["--profile", profile]
    return cmd


def ensure_networks() -> int:
    """Create the on-demand networks that do not exist yet (idempotent)."""
    for name, internal in ON_DEMAND_NETWORKS:
        probe = subprocess.run(  # noqa: S603
            ["docker", "network", "inspect", name], capture_output=True, text=True, check=False  # noqa: S607
        )
        if probe.returncode == 0:
            continue
        cmd = ["docker", "network", "create"] + (["--internal"] if internal else []) + [name]
        if run(cmd) != 0:
            return 1
    return 0


def dd_database_url(password: str) -> str:
    """DefectDojo's database URL (a secret: it holds the password). TLS is verified against our CA."""
    quoted = urllib.parse.quote(password, safe="")
    return (
        f"postgresql://defectdojo:{quoted}@db:5432/defectdojo"
        "?sslmode=verify-full&sslrootcert=/run/secrets/tls_ca"
    )


def cmd_secrets_init(_: argparse.Namespace) -> int:
    SECRETS.mkdir(parents=True, exist_ok=True)
    for name, size in GENERATED_SECRETS.items():
        path = SECRETS / name
        if path.exists():
            print(f"keep   {name}")
            continue
        value = b"" if size is None else pysecrets.token_hex(size).encode("ascii")
        path.write_bytes(value)  # binary mode: no CRLF translation, no trailing newline
        path.chmod(0o644)
        print(f"create {name}")
    # Derived from defectdojo_db_password (DefectDojo reads it through DD_DATABASE_URL_FILE, so the
    # password never sits in an environment variable).
    url_path = SECRETS / "dd_database_url"
    if url_path.exists():
        print("keep   dd_database_url")
    else:
        password = (SECRETS / "defectdojo_db_password").read_bytes().decode("ascii").strip()
        url_path.write_bytes(dd_database_url(password).encode("ascii"))
        url_path.chmod(0o644)
        print("create dd_database_url")
    return 0


def cmd_certs(_: argparse.Namespace) -> int:
    if shutil.which("openssl") is None:
        print("openssl not found; install it (apt install openssl)", file=sys.stderr)
        return 1
    TLS.mkdir(parents=True, exist_ok=True)
    ca_key, ca_crt = TLS / "ca.key", TLS / "ca.crt"
    srv_key, srv_crt, srv_csr = TLS / "server.key", TLS / "server.crt", TLS / "server.csr"
    ext = TLS / "server.ext"
    if srv_crt.exists() and srv_key.exists():
        print("certificates already exist; delete deploy/secrets/tls to regenerate")
        return 0
    san = ",".join(f"DNS:{h}" for h in TLS_HOSTS)
    ext.write_text(f"subjectAltName={san}\nextendedKeyUsage=serverAuth\n", encoding="ascii")
    steps = [
        ["openssl", "req", "-x509", "-newkey", "rsa:4096", "-nodes", "-days", "825", "-keyout",
         str(ca_key), "-out", str(ca_crt), "-subj", "/CN=SecureScan Development CA"],
        ["openssl", "req", "-newkey", "rsa:3072", "-nodes", "-keyout", str(srv_key), "-out",
         str(srv_csr), "-subj", "/CN=securescan.localtest.me"],
        ["openssl", "x509", "-req", "-in", str(srv_csr), "-CA", str(ca_crt), "-CAkey", str(ca_key),
         "-CAcreateserial", "-out", str(srv_crt), "-days", "825", "-extfile", str(ext)],
    ]
    for step in steps:
        if run(step) != 0:
            return 1
    for path in (ca_crt, srv_crt, srv_key):
        path.chmod(0o644)  # development only; see deploy/secrets/README.md
    srv_csr.unlink(missing_ok=True)
    return 0


def cmd_pin_images(_: argparse.Namespace) -> int:
    return run([sys.executable, str(ROOT / "scripts" / "pin_images.py")])


def cmd_pull_images(_: argparse.Namespace) -> int:
    images_env = DEPLOY / "images.env"
    if not images_env.exists():
        print("run `dev.py pin-images` first", file=sys.stderr)
        return 1
    failures = 0
    for line in images_env.read_text(encoding="utf-8").splitlines():
        if not line.startswith("IMG_") or "=" not in line:
            continue
        name, ref = line.split("=", 1)
        if name == "IMG_SPOTBUGS_FSB":
            continue  # built locally
        failures += run(["docker", "pull", ref]) != 0
    failures += pull_approved_overlays()
    return 1 if failures else 0


def pull_approved_overlays() -> int:
    """Pull the images of approved image updates (they are not in images.env). Skipped while the stack is down."""
    probe = subprocess.run(  # noqa: S603
        compose_base() + ["exec", "-T", "api", "python", "-m", "securescan.domain.image_updates", "active"],
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode != 0:
        print("approved image updates not read (the stack is not running); run pull-images again after `up`")
        return 0
    failures = 0
    for line in probe.stdout.splitlines():
        ref = line.strip()
        if ref:
            failures += run(["docker", "pull", ref]) != 0
    return failures


def cmd_up(args: argparse.Namespace) -> int:
    profiles = args.profile or []
    if ensure_networks() != 0:
        return 1
    return run(compose_base(profiles) + ["up", "-d", "--build"])


def cmd_down(args: argparse.Namespace) -> int:
    cmd = compose_base(["dev"]) + ["down"]
    if args.volumes:
        cmd.append("--volumes")
    return run(cmd)


def cmd_logs(args: argparse.Namespace) -> int:
    return run(compose_base(["dev"]) + ["logs", "-f", args.service])


def cmd_networks(_: argparse.Namespace) -> int:
    return ensure_networks()


def cmd_migrate(_: argparse.Namespace) -> int:
    if ensure_networks() != 0:
        return 1
    return run(compose_base() + ["run", "--rm", "migrate"])


def cmd_test(args: argparse.Namespace) -> int:
    kind = args.kind
    env = dict(os.environ)
    if kind in ("unit", "all"):
        if run(["uv", "run", "pytest", "tests/unit"], cwd=ROOT / "backend") != 0:
            return 1
        if (ROOT / "frontend" / "node_modules").exists():
            if run(["npm", "test"], cwd=ROOT / "frontend") != 0:
                return 1
    if kind in ("integration", "contract"):
        env["SECURESCAN_INTEGRATION"] = "1"
        return run(["uv", "run", "pytest", f"tests/{kind}", "-m", "integration or not integration"],
                   cwd=ROOT / "backend", env=env)
    if kind == "e2e":
        return run(["npm", "run", "e2e"], cwd=ROOT / "frontend")
    if kind == "regression":
        base = compose_base()
        worker = ["exec", "-T", "worker", "python", "-m", "securescan.domain.regression"]
        if run(base + worker + ["check"]) != 0:
            return 1
        return run(base + worker + ["run", "--kind", "all"])
    return 0


def cmd_fetch_fixtures(_: argparse.Namespace) -> int:
    target = ROOT / "fixtures" / "external"
    target.mkdir(parents=True, exist_ok=True)
    repos = {
        "juice-shop": "https://github.com/juice-shop/juice-shop.git",
        "WebGoat": "https://github.com/WebGoat/WebGoat.git",
    }
    for name, url in repos.items():
        dest = target / name
        if dest.exists():
            print(f"keep {name}")
            continue
        if run(["git", "clone", "--depth", "1", url, str(dest)]) != 0:
            return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dev.py", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    secrets_p = sub.add_parser("secrets", help="manage generated secrets")
    secrets_sub = secrets_p.add_subparsers(dest="action", required=True)
    secrets_sub.add_parser("init", help="create missing generated secrets").set_defaults(
        func=cmd_secrets_init
    )
    sub.add_parser("certs", help="generate a self-signed development certificate").set_defaults(
        func=cmd_certs
    )
    sub.add_parser("pin-images", help="resolve image digests").set_defaults(func=cmd_pin_images)
    sub.add_parser("pull-images", help="pre-pull every pinned image").set_defaults(
        func=cmd_pull_images
    )
    up = sub.add_parser("up", help="start the stack")
    up.add_argument("--profile", action="append", help="compose profile (dev, test)")
    up.set_defaults(func=cmd_up)
    down = sub.add_parser("down", help="stop the stack")
    down.add_argument("--volumes", action="store_true", help="also delete volumes")
    down.set_defaults(func=cmd_down)
    logs = sub.add_parser("logs", help="follow logs of a service")
    logs.add_argument("service")
    logs.set_defaults(func=cmd_logs)
    sub.add_parser("networks", help="create the on-demand Docker networks").set_defaults(
        func=cmd_networks
    )
    sub.add_parser("migrate", help="run database migrations").set_defaults(func=cmd_migrate)
    test = sub.add_parser("test", help="run tests")
    test.add_argument(
        "kind", nargs="?", default="unit",
        choices=["unit", "integration", "contract", "e2e", "regression", "all"],
    )
    test.set_defaults(func=cmd_test)
    sub.add_parser("fetch-fixtures", help="clone Juice Shop and WebGoat").set_defaults(
        func=cmd_fetch_fixtures
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
