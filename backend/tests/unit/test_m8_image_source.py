"""Image intake: references, root file system extraction (whiteouts, links, traversal), skopeo run, uploads."""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
import tarfile
import types
import uuid
from pathlib import Path
from typing import Any

import pytest

from securescan.config import Settings, get_settings
from securescan.runner.catalogue import clear_catalogue_cache
from securescan.runner.sources import image as image_source
from securescan.runner.sources.base import SourceError
from securescan.runner.sources.image import (
    ExtractLimits,
    ImageReference,
    acquire_image,
    clean_parts,
    collect_java_archives,
    explain_skopeo_failure,
    extract_image_archive,
    is_direct_registry,
    parse_image_reference,
    parse_registry_secret,
    registry_hosts,
    render_auth_file,
)
from securescan.runner.workspace import Workspace
from tests.unit.conftest import FakeSession
from tests.unit.m8_helpers import (
    PROXY,
    FakeLauncher,
    can_symlink,
    docker_archive,
    host_path_of,
    lease_factory,
    layer_tar,
    put_file,
    set_pin,
)
from tests.unit.runner_helpers import REPO_SCANNERS

DIR = tarfile.DIRTYPE


# --------------------------------------------------------------------------- references
@pytest.mark.parametrize(
    ("text", "registry", "repository", "tag", "digest"),
    [
        ("nginx", "docker.io", "library/nginx", None, None),
        ("nginx:1.27", "docker.io", "library/nginx", "1.27", None),
        ("team/app:2", "docker.io", "team/app", "2", None),
        ("ghcr.io/org/app:1.2", "ghcr.io", "org/app", "1.2", None),
        ("registry.local:5000/team/app@sha256:" + "a" * 64, "registry.local:5000", "team/app", None, "sha256:" + "a" * 64),
        ("docker://quay.io/a/b:v1", "quay.io", "a/b", "v1", None),
        ("localhost/app:1", "localhost", "app", "1", None),
        ("index.docker.io/library/redis:7", "docker.io", "library/redis", "7", None),
        ("  ghcr.io/org/app:1  ", "ghcr.io", "org/app", "1", None),
    ],
)
def test_valid_references(text: str, registry: str, repository: str, tag: str | None, digest: str | None) -> None:
    reference = parse_image_reference(text)
    assert (reference.registry, reference.repository, reference.tag, reference.digest) == (registry, repository, tag, digest)
    assert reference.docker_url == "docker://" + reference.name and reference.name.startswith(registry + "/")


@pytest.mark.parametrize(
    "text",
    [
        "", "   ", "-x", "--help", "a b", "app;rm -rf /", "app$(id)", "app`id`", "app|x", "UPPER/case", "a/b:tag with space",
        "x@sha256:short", "a" * 400, "https://example.com/y", "a//b", "reg.io/", "app:", "app:-bad", "../../etc", "a/../b",
        "app\nname", "app'x", 'app"x', "reg.io:99999999/app",
    ],
)
def test_references_that_could_be_used_for_injection_are_refused(text: str) -> None:
    with pytest.raises(SourceError) as info:
        parse_image_reference(text)
    assert info.value.code == "image.bad_reference"


def test_registry_hosts_for_the_egress_allowlist() -> None:
    hub = registry_hosts(parse_image_reference("nginx"))
    assert hub == ["registry-1.docker.io", "auth.docker.io", "production.cloudflare.docker.com"]
    assert registry_hosts(parse_image_reference("ghcr.io/o/a:1")) == ["ghcr.io", "pkg-containers.githubusercontent.com"]
    assert registry_hosts(parse_image_reference("reg.example.com:8443/a:1")) == ["reg.example.com"], "the port is not part of a host name"


def test_registries_reached_directly() -> None:
    local = parse_image_reference("registry.local:5000/a:1")
    assert is_direct_registry(local, "registry.local:5000, other.example") and is_direct_registry(local, "REGISTRY.LOCAL")
    assert not is_direct_registry(local, "") and not is_direct_registry(parse_image_reference("ghcr.io/a:1"), "registry.local")


def test_registry_secrets_and_the_auth_file() -> None:
    assert parse_registry_secret('{"username": "u", "password": "p:w"}') == ("u", "p:w")
    assert parse_registry_secret("user:pa:ss\n") == ("user", "pa:ss")
    for bad in ("", "nocolon", ":nopassword", "user:", "{bad json", '{"username": "u"}'):
        with pytest.raises(SourceError):
            parse_registry_secret(bad)
    auth = json.loads(render_auth_file("ghcr.io", "u", "p"))
    assert base64.b64decode(auth["auths"]["ghcr.io"]["auth"]) == b"u:p"


def test_skopeo_failures_are_explained_without_echoing_anything_secret() -> None:
    ref = parse_image_reference("ghcr.io/org/app:1")
    assert "refused access" in explain_skopeo_failure("Error: unauthorized: authentication required", ref)
    assert "was not found" in explain_skopeo_failure("manifest unknown: manifest unknown", ref)
    assert "could not be found by name" in explain_skopeo_failure("dial tcp: lookup ghcr.io: no such host", ref)
    assert "certificate" in explain_skopeo_failure("x509: certificate signed by unknown authority", ref)
    proxy = explain_skopeo_failure("proxyconnect tcp: 403 Forbidden", ref)
    assert "egress proxy" in proxy and "SECURESCAN_IMAGE_REGISTRY_DIRECT_HOSTS" in proxy
    assert "details are in the job log" in explain_skopeo_failure("something odd", ref)


# --------------------------------------------------------------------------- path rules
def test_member_names_may_not_leave_the_image() -> None:
    assert clean_parts("./etc//passwd") == ["etc", "passwd"] and clean_parts("/abs/file") == ["abs", "file"]
    assert clean_parts("a\\b") == ["a", "b"] and clean_parts("./") == []
    for evil in ("../evil", "a/../../evil", "/../x", "a/b/../../../c"):
        with pytest.raises(SourceError) as info:
            clean_parts(evil)
        assert info.value.code == "image.path_traversal"
    with pytest.raises(SourceError):
        clean_parts("nul\x00byte")


# --------------------------------------------------------------------------- extraction
def test_layers_are_applied_in_order_with_whiteouts_and_opaque_directories(tmp_path: Path) -> None:
    lower = layer_tar([
        ("etc/", b"", DIR), ("etc/a.conf", b"A"), ("etc/b.conf", b"B"),
        ("app/", b"", DIR), ("app/old.txt", b"old"), ("app/keep/", b"", DIR), ("app/keep/x", b"x"),
        ("usr/bin/tool", b"#!x", tarfile.REGTYPE, 0o755), ("data", b"i am a file"),
    ])  # fmt: skip
    upper = layer_tar([
        ("etc/.wh.a.conf", b""), ("app/.wh..wh..opq", b""), ("app/new.txt", b"new"),
        ("dev/null", b"", tarfile.CHRTYPE), ("dev/sda", b"", tarfile.BLKTYPE), ("run/fifo", b"", tarfile.FIFOTYPE),
        ("data/", b"", DIR), ("data/inner", b"1"),
    ])  # fmt: skip
    archive = docker_archive(tmp_path / "image.tar", [lower, upper], image_id="cafe01", tags=["demo:1"])
    root = tmp_path / "rootfs"
    summary = extract_image_archive(archive, root)
    assert not (root / "etc/a.conf").exists(), "whiteout of a file"
    assert (root / "etc/b.conf").read_bytes() == b"B"
    assert not (root / "app/old.txt").exists() and not (root / "app/keep").exists(), "opaque directory empties lower layers"
    assert (root / "app/new.txt").read_bytes() == b"new", "files of the same layer survive its own opaque marker"
    assert (root / "data/inner").read_bytes() == b"1", "a directory replaces a file of a lower layer"
    for special in ("dev/null", "dev/sda", "run/fifo"):
        assert not (root / special).exists(), special
    assert summary.layers == 2 and summary.whiteouts == 2 and summary.skipped_special == 3
    assert summary.image_id == "cafe01" and summary.repo_tags == ["demo:1"]
    if os.name != "nt":
        assert os.stat(root / "usr/bin/tool").st_mode & 0o111 and not os.stat(root / "etc/b.conf").st_mode & 0o111


def test_an_entry_that_leaves_the_root_rejects_the_image(tmp_path: Path) -> None:
    for index, evil in enumerate(["../evil", "a/../../evil", "/../x/../../y", "etc/.wh.../../x"]):
        archive = docker_archive(tmp_path / f"bad{index}.tar", [layer_tar([(evil, b"x")])])
        with pytest.raises(SourceError) as info:
            extract_image_archive(archive, tmp_path / f"root{index}")
        assert info.value.code == "image.path_traversal", evil
    assert not (tmp_path / "evil").exists() and not (tmp_path.parent / "evil").exists()


def test_absolute_member_names_stay_inside_the_root(tmp_path: Path) -> None:
    archive = docker_archive(tmp_path / "abs.tar", [layer_tar([("/abs/file", b"1")])])
    extract_image_archive(archive, tmp_path / "root")
    assert (tmp_path / "root/abs/file").read_bytes() == b"1"


def test_size_and_entry_limits(tmp_path: Path) -> None:
    archive = docker_archive(tmp_path / "big.tar", [layer_tar([("f", b"x" * 5000)])])
    with pytest.raises(SourceError) as info:
        extract_image_archive(archive, tmp_path / "r1", ExtractLimits(max_bytes=1000))
    assert info.value.code == "image.too_large"
    many = docker_archive(tmp_path / "many.tar", [layer_tar([(f"d/f{i}", b"") for i in range(10)])])
    with pytest.raises(SourceError) as info:
        extract_image_archive(many, tmp_path / "r2", ExtractLimits(max_entries=5))
    assert info.value.code == "image.too_many_entries"


def test_links_are_rewritten_inside_the_root_and_cannot_be_written_through_out_of_it(tmp_path: Path) -> None:
    if not can_symlink(tmp_path):
        pytest.skip("symbolic links are not available here")
    layer = layer_tar([
        ("usr/", b"", DIR), ("usr/lib/", b"", DIR), ("usr/lib/real.so", b"S"),
        ("lib", b"", tarfile.SYMTYPE, 0o777, "usr/lib"),
        ("bin", b"", tarfile.SYMTYPE, 0o777, "/usr/lib"),
        ("etc/", b"", DIR),
        ("etc/passwd.link", b"", tarfile.SYMTYPE, 0o777, "../../../../../../etc/passwd"),
        ("etc/abs.link", b"", tarfile.SYMTYPE, 0o777, "/usr/lib/real.so"),
        ("lib/more.so", b"M"),
        ("hard.so", b"", tarfile.LNKTYPE, 0o644, "usr/lib/real.so"),
    ])  # fmt: skip
    root = tmp_path / "root"
    summary = extract_image_archive(docker_archive(tmp_path / "links.tar", [layer]), root)
    assert (root / "usr/lib/more.so").read_bytes() == b"M", "a write through a link lands where the link points inside the root"
    assert os.readlink(root / "etc/abs.link") == "../usr/lib/real.so", "absolute targets become relative"
    assert os.readlink(root / "bin") == "usr/lib"
    resolved = os.path.normpath(os.path.join(str(root / "etc"), os.readlink(root / "etc/passwd.link")))
    assert os.path.commonpath([resolved, str(root)]) == str(root), "a link out of the root is clamped to it"
    assert (root / "hard.so").read_bytes() == b"S" and summary.hardlinks == 1
    escape = layer_tar([
        ("etc/", b"", DIR), ("etc/escape", b"", tarfile.SYMTYPE, 0o777, "../../../../outside"),
        ("etc/escape/pwned", b"P"),
    ])  # fmt: skip
    root2 = tmp_path / "root2"
    extract_image_archive(docker_archive(tmp_path / "escape.tar", [escape]), root2)
    assert not (tmp_path / "outside").exists() and not (tmp_path.parent / "outside").exists()
    assert (root2 / "outside/pwned").read_bytes() == b"P"


def test_a_loop_of_links_is_an_error_not_a_hang(tmp_path: Path) -> None:
    if not can_symlink(tmp_path):
        pytest.skip("symbolic links are not available here")
    layer = layer_tar([
        ("a", b"", tarfile.SYMTYPE, 0o777, "b"), ("b", b"", tarfile.SYMTYPE, 0o777, "a"), ("a/file", b"x"),
    ])  # fmt: skip
    with pytest.raises(SourceError) as info:
        extract_image_archive(docker_archive(tmp_path / "loop.tar", [layer]), tmp_path / "root")
    assert info.value.code in ("image.link_loop", "image.bad_archive")


def test_oci_layouts_with_compressed_layers_are_read(tmp_path: Path) -> None:
    layer = gzip.compress(layer_tar([("srv/hello", b"hi")]))
    layer_digest = "sha256:" + hashlib.sha256(layer).hexdigest()
    config = b"{}"
    config_digest = "sha256:" + hashlib.sha256(config).hexdigest()
    manifest = json.dumps({"schemaVersion": 2, "config": {"digest": config_digest}, "layers": [{"digest": layer_digest}]}).encode()
    manifest_digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
    index = json.dumps({"schemaVersion": 2, "manifests": [
        {"digest": "sha256:" + "0" * 64, "platform": {"os": "linux", "architecture": "arm64"}},
        {"digest": manifest_digest, "platform": {"os": "linux", "architecture": "amd64"}},
    ]}).encode()  # fmt: skip
    path = tmp_path / "oci.tar"
    with tarfile.open(path, "w") as outer:
        for name, data in [("index.json", index), ("blobs/sha256/" + manifest_digest[7:], manifest),
                           ("blobs/sha256/" + layer_digest[7:], layer), ("blobs/sha256/" + config_digest[7:], config)]:  # fmt: skip
            info = tarfile.TarInfo(name)
            info.size = len(data)
            outer.addfile(info, io.BytesIO(data))
    summary = extract_image_archive(path, tmp_path / "root")
    assert (tmp_path / "root/srv/hello").read_bytes() == b"hi" and summary.image_id == config_digest[7:]


def test_files_that_are_not_image_archives_are_refused(tmp_path: Path) -> None:
    plain = tmp_path / "plain.tar"
    with tarfile.open(plain, "w") as outer:
        info = tarfile.TarInfo("readme")
        info.size = 1
        outer.addfile(info, io.BytesIO(b"x"))
    with pytest.raises(SourceError) as info_:
        extract_image_archive(plain, tmp_path / "r1")
    assert info_.value.code == "image.bad_archive"
    junk = tmp_path / "junk"
    junk.write_bytes(b"this is not a tar file" * 100)
    with pytest.raises(SourceError) as info_:
        extract_image_archive(junk, tmp_path / "r2")
    assert info_.value.code == "image.bad_archive"
    missing_layer = tmp_path / "missing.tar"
    with tarfile.open(missing_layer, "w") as outer:
        manifest = json.dumps([{"Config": "c.json", "Layers": ["nope/layer.tar"]}]).encode()
        info = tarfile.TarInfo("manifest.json")
        info.size = len(manifest)
        outer.addfile(info, io.BytesIO(manifest))
    with pytest.raises(SourceError) as info_:
        extract_image_archive(missing_layer, tmp_path / "r3")
    assert info_.value.code == "image.bad_archive"


# --------------------------------------------------------------------------- Java archives
def test_java_archives_of_the_application_are_collected_without_the_jdk(tmp_path: Path) -> None:
    src = tmp_path / "src"
    for relative in ("rootfs/app/app.jar", "rootfs/usr/lib/jvm/java-17/lib/rt.jar", "rootfs/opt/openjdk/x.jar",
                     "rootfs/srv/a.war", "rootfs/srv/readme.txt", "rootfs/deploy/b.ear"):  # fmt: skip
        put_file(src, relative)
    assert collect_java_archives(src, src / "rootfs") == ["rootfs/app/app.jar", "rootfs/deploy/b.ear", "rootfs/srv/a.war"]
    assert collect_java_archives(src, src / "rootfs", limit=1) == ["rootfs/app/app.jar"]


# --------------------------------------------------------------------------- the source handler
@pytest.fixture
def catalogue_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESCAN_SCANNERS_DIR", str(REPO_SCANNERS))
    get_settings.cache_clear()
    clear_catalogue_cache()
    set_pin(monkeypatch, "SKOPEO", "quay.io/skopeo/stable")


def make_request(session: Any = None, **target: Any) -> Any:
    workspace = Workspace.create(uuid.uuid4())
    logs: list[str] = []

    async def log(line: str) -> None:
        logs.append(line)

    values: dict[str, Any] = {"kind": "image", "locator": None, "upload_artifact_id": None, "credential_id": None}
    values.update(target)
    request = types.SimpleNamespace(
        session=session or FakeSession(),
        scan=types.SimpleNamespace(id=uuid.uuid4()),
        target=types.SimpleNamespace(**values),
        workspace=workspace,
        settings=Settings(),
        log=log,
    )
    request.logs = logs
    return request


def sample_archive(tmp_path: Path) -> Path:
    layer = layer_tar([("app/", b"", DIR), ("app/run.jar", b"PK"), ("app/main.py", b"print(1)"), ("etc/os-release", b"x")])
    return docker_archive(tmp_path / "sample.tar", [layer], image_id="feed99", tags=["app:1"])


async def test_an_uploaded_archive_is_unpacked_and_kept_for_syft(tmp_path: Path) -> None:
    from securescan.storage.artifacts import resolve_key

    source = sample_archive(tmp_path)
    key = "uploads/2026/10/abc"
    target_file = resolve_key(key)
    target_file.parent.mkdir(parents=True, exist_ok=True)
    target_file.write_bytes(source.read_bytes())
    artifact = types.SimpleNamespace(id=uuid.uuid4(), deleted_at=None, filename="app.tar", storage_key=key)
    session = FakeSession()
    session.added.append(artifact)
    request = make_request(session, upload_artifact_id=artifact.id)
    info = await acquire_image(request)
    assert info.kind == "image" and info.is_git is False and "uploaded image archive app.tar" in info.description
    workspace: Workspace = request.workspace
    assert (workspace.config / "image.tar").is_file(), "Syft reads the archive from the config mount"
    assert (workspace.src / "rootfs/app/main.py").read_bytes() == b"print(1)"
    assert not (workspace.src / "image.tar").exists(), "the archive is not scanned as source"
    assert info.details["java_archives"] == ["rootfs/app/run.jar"] and info.details["image_id"] == "feed99"
    assert info.details["repo_tags"] == ["app:1"]
    assert any("unpacked 1 layers" in line for line in request.logs)


async def test_a_deleted_upload_is_a_plain_error(tmp_path: Path) -> None:
    request = make_request(upload_artifact_id=uuid.uuid4())
    with pytest.raises(SourceError) as info:
        await acquire_image(request)
    assert info.value.code == "image.upload_missing"


class SkopeoRun:
    """A fake ``skopeo`` that writes the archive and remembers what it was given."""

    def __init__(self, archive: Path, exit_code: int = 0, logs: str = "") -> None:
        self.archive = archive
        self.exit_code = exit_code
        self.auth_during_run: dict[str, Any] | None = None
        self.launcher = FakeLauncher(self.run, logs=logs)

    def run(self, spec: Any) -> int:
        config = host_path_of(spec, "/config")
        auth = config / "auth.json"
        if auth.exists():
            self.auth_during_run = {"text": auth.read_text(encoding="utf-8"), "mode": auth.stat().st_mode & 0o777}
        if self.exit_code == 0:
            out = host_path_of(spec, "/out")
            (out / "image.tar").write_bytes(self.archive.read_bytes())
        return self.exit_code


@pytest.fixture
def skopeo(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, catalogue_env: None) -> SkopeoRun:
    from securescan.runner import egress, launcher

    run = SkopeoRun(sample_archive(tmp_path))
    monkeypatch.setattr(launcher, "get_launcher", lambda: run.launcher)
    seen: list[Any] = []
    monkeypatch.setattr(egress, "egress_lease", lease_factory(PROXY, seen))
    run.seen_hosts = seen  # type: ignore[attr-defined]
    return run


async def test_a_registry_image_is_copied_through_the_egress_proxy_and_unpacked(skopeo: SkopeoRun) -> None:
    request = make_request(locator="ghcr.io/org/app:1.2")
    info = await acquire_image(request)
    spec = skopeo.launcher.specs[0]
    assert spec.command == ["copy", "--retry-times", "2", "docker://ghcr.io/org/app:1.2", "docker-archive:/out/image.tar"]
    assert spec.env["HTTPS_PROXY"] == PROXY and spec.env["TMPDIR"] == "/out/tmp"
    assert "REGISTRY_AUTH_FILE" not in spec.env
    assert spec.network == request.settings.network_backend and spec.user == "1000:1000" and spec.read_only_rootfs is True
    assert spec.name == f"securescan-job-{request.workspace.job_id}-skopeo"
    assert skopeo.seen_hosts == [["ghcr.io", "pkg-containers.githubusercontent.com"]]  # type: ignore[attr-defined]
    assert [ro for _s, target, ro in spec.binds if target == "/config"] == [True]
    assert (request.workspace.src / "rootfs/app/main.py").is_file() and (request.workspace.config / "image.tar").is_file()
    assert not (request.workspace.out / "image.tar").exists() and not (request.workspace.out / "tmp").exists()
    assert info.description == "image ghcr.io/org/app:1.2" and info.notes == []


async def test_a_reference_without_a_tag_is_noted(skopeo: SkopeoRun) -> None:
    info = await acquire_image(make_request(locator="registry.example.com/team/app"))
    assert any("no tag or digest" in note for note in info.notes)


async def test_the_registry_credential_is_a_private_file_for_that_container_only(skopeo: SkopeoRun, monkeypatch: pytest.MonkeyPatch) -> None:
    async def secret(_request: Any, _reference: ImageReference) -> tuple[str, str]:
        return "robot", "s3cr3t-pw"

    monkeypatch.setattr(image_source, "_registry_secret", secret)
    request = make_request(locator="ghcr.io/org/app:1")
    await acquire_image(request)
    spec = skopeo.launcher.specs[0]
    assert spec.env["REGISTRY_AUTH_FILE"] == "/config/auth.json"
    assert skopeo.auth_during_run is not None
    auth = json.loads(skopeo.auth_during_run["text"])
    assert base64.b64decode(auth["auths"]["ghcr.io"]["auth"]) == b"robot:s3cr3t-pw"
    if os.name != "nt":
        assert skopeo.auth_during_run["mode"] == 0o600
    assert not (request.workspace.config / "auth.json").exists(), "removed after the run"
    haystack = " ".join([*spec.command, *spec.env.values(), *spec.env.keys()])
    assert "s3cr3t-pw" not in haystack and "robot" not in haystack, "no secret on the command line or in the environment"


async def test_a_registry_on_the_local_network_is_reached_without_the_proxy(skopeo: SkopeoRun, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURESCAN_IMAGE_REGISTRY_DIRECT_HOSTS", "registry.local:5000")
    request = make_request(locator="registry.local:5000/team/app:3")
    await acquire_image(request)
    spec = skopeo.launcher.specs[0]
    assert "HTTPS_PROXY" not in spec.env and skopeo.seen_hosts == []  # type: ignore[attr-defined]
    assert spec.command[3] == "docker://registry.local:5000/team/app:3"


@pytest.mark.parametrize(
    ("logs", "fragment"),
    [("Error: unauthorized: authentication required", "refused access"), ("manifest unknown", "was not found")],
)
async def test_a_failing_copy_is_explained(skopeo: SkopeoRun, logs: str, fragment: str) -> None:
    skopeo.launcher.on_run = lambda spec: 1
    skopeo.launcher.logs = logs
    request = make_request(locator="ghcr.io/org/app:1")
    with pytest.raises(SourceError) as info:
        await acquire_image(request)
    assert info.value.code == "image.pull_failed" and fragment in str(info.value)
    assert not (request.workspace.config / "auth.json").exists()


async def test_a_bad_reference_never_reaches_docker(skopeo: SkopeoRun) -> None:
    with pytest.raises(SourceError) as info:
        await acquire_image(make_request(locator="app;touch /tmp/x"))
    assert info.value.code == "image.bad_reference" and skopeo.launcher.specs == []


def test_the_handler_is_registered_for_image_targets() -> None:
    from securescan.runner.sources import supported_kinds
    from securescan.runner.tools import get_builder

    get_builder("syft-grype")  # loading the tool registry imports the module that registers the handler
    assert "image" in supported_kinds()
