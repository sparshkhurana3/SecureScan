"""Image intake: a registry reference or an uploaded archive becomes ``config/image.tar`` and ``src/rootfs``.

Source handler for targets of kind ``image`` (plan M8 task 1). It is registered by ``register_image_source()``,
which the Syft/Grype tool module calls when the tool registry loads (before the executor acquires a source).

1. **Get the archive.**
   * An uploaded archive (``Target.upload_artifact_id``) is copied into the workspace.
   * A registry reference (``Target.locator``, for example ``registry.example.com/team/app:1.4`` or
     ``ghcr.io/org/app@sha256:...``) is validated strictly (never passed to a shell, never starting with ``-``) and
     copied by ``skopeo copy docker://<ref> docker-archive:/out/image.tar`` in a container (catalogue entry
     ``skopeo``, no capabilities). The container joins the egress client network and reaches the registry only
     through the shared egress proxy, whose allowlist is exactly the registry's hosts (a registry listed in
     ``SECURESCAN_IMAGE_REGISTRY_DIRECT_HOSTS`` is reached directly, for a registry on the local network). A stored
     registry credential (``CredentialKind.REGISTRY``, ``user:password`` or JSON ``{"username", "password"}``)
     becomes a 0600 ``auth.json`` in the job's ``config`` directory (``REGISTRY_AUTH_FILE``) for this container only
     and is deleted afterwards. Nothing secret is on a command line.
   The archive ends up in ``config/image.tar`` (not in ``src``, so that Gitleaks and Semgrep do not
   scan the compressed layers a second time); Syft reads it as ``docker-archive:/config/image.tar``.
2. **Extract the root filesystem** into ``src/rootfs`` for the file-based tools (``extract_image_archive``):
   layers are applied in order; ``.wh.<name>`` whiteouts delete lower-layer paths and ``.wh..wh..opq`` empties a
   directory of lower layers (whiteouts of a layer are applied before that layer's own files); device nodes,
   fifos and sockets are skipped; symbolic links are rewritten to relative links inside the root, and a link that
   would leave the root is clamped to it, as a chroot would; hard links are copied; an entry that tries to leave
   the root (``..``) rejects the image; sizes and entry counts are capped.
3. **Collect** the JAR, WAR and EAR files for SpotBugs (``details["java_archives"]``).

Supported archives: ``docker save`` / skopeo ``docker-archive`` (``manifest.json``) and OCI image layouts
(``index.json`` with ``blobs/sha256/...``), compressed layers included.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import posixpath
import re
import shutil
import tarfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from securescan.logging import get_logger, scrub
from securescan.runner.sources import register_source_handler
from securescan.runner.sources.base import SourceError, SourceInfo, SourceRequest

log = get_logger(__name__)

ARCHIVE_NAME = "image.tar"
ROOTFS_DIR = "rootfs"
AUTH_FILE = "auth.json"
SKOPEO_TOOL = "skopeo"
WHITEOUT = ".wh."
OPAQUE = ".wh..wh..opq"
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_SYMLINK_HOPS = 40
CHUNK = 1024 * 1024
JAVA_SUFFIXES = (".jar", ".war", ".ear")
MAX_JAVA_ARCHIVES = 400
JDK_DIRECTORY_PREFIXES = ("openjdk", "jdk", "jre", "java-1", "java-2", "temurin", "zulu", "corretto")
JDK_DIRECTORIES = frozenset({"jvm", "jdk", "jre"})

# Hosts a registry's blobs come from, besides the registry itself (redirects to a CDN or an auth service).
REGISTRY_EXTRA_HOSTS = {
    "docker.io": ("registry-1.docker.io", "auth.docker.io", "production.cloudflare.docker.com"),
    "ghcr.io": ("ghcr.io", "pkg-containers.githubusercontent.com"),
    "quay.io": ("quay.io", "cdn.quay.io", "cdn01.quay.io", "cdn02.quay.io", "cdn03.quay.io"),
}

_REGISTRY = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(?::[0-9]{1,5})?$")
_PATH_COMPONENT = re.compile(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$")
_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


# --------------------------------------------------------------------------- the reference
@dataclass(frozen=True)
class ImageReference:
    registry: str  # with port when given, ``docker.io`` for Docker Hub
    repository: str  # ``library/nginx``
    tag: str | None
    digest: str | None

    @property
    def name(self) -> str:
        text = f"{self.registry}/{self.repository}"
        if self.tag:
            text += f":{self.tag}"
        if self.digest:
            text += f"@{self.digest}"
        return text

    @property
    def docker_url(self) -> str:
        return f"docker://{self.name}"

    @property
    def registry_host(self) -> str:
        return self.registry.rsplit(":", 1)[0] if re.search(r":[0-9]+$", self.registry) else self.registry


def parse_image_reference(text: str) -> ImageReference:
    """A validated reference. Raises ``SourceError`` (plain language) for anything that is not one."""
    value = (text or "").strip()
    if value.startswith("docker://"):
        value = value[len("docker://") :]
    if not value or len(value) > 300:
        raise SourceError("The image reference is empty or too long.", code="image.bad_reference")
    if value.startswith("-") or any(ch.isspace() or ord(ch) < 32 or ch in "'\"`$;|&<>\\" for ch in value):
        raise SourceError("The image reference contains characters that are not allowed.", code="image.bad_reference")
    name, _, digest = value.partition("@")
    if digest and not _DIGEST.match(digest):
        raise SourceError("The image digest must look like sha256:<64 hex characters>.", code="image.bad_reference")
    path_part = name
    tag: str | None = None
    last = name.rsplit("/", 1)[-1]
    if ":" in last:
        path_part, _, tag = name.rpartition(":")
        if not _TAG.match(tag):
            raise SourceError("The image tag is not valid.", code="image.bad_reference")
    components = path_part.split("/")
    registry = "docker.io"
    first = components[0]
    if len(components) > 1 and ("." in first or ":" in first or first == "localhost"):
        registry = first
        components = components[1:]
    if not _REGISTRY.match(registry):
        raise SourceError("The registry address of the image reference is not valid.", code="image.bad_reference")
    if registry in ("docker.io", "index.docker.io") and len(components) == 1:
        components = ["library", *components]
    if registry == "index.docker.io":
        registry = "docker.io"
    if not components or not all(_PATH_COMPONENT.match(part) for part in components):
        raise SourceError(
            "The repository name of the image reference is not valid (lower-case letters, digits, . _ - and /).",
            code="image.bad_reference",
        )
    return ImageReference(registry=registry, repository="/".join(components), tag=tag, digest=digest or None)


def registry_hosts(reference: ImageReference) -> list[str]:
    """Hosts the egress proxy must allow for this registry (the registry and its known blob hosts)."""
    known = REGISTRY_EXTRA_HOSTS.get(reference.registry_host)
    hosts = list(known) if known else [reference.registry_host]
    return [h.lower() for h in hosts]


def is_direct_registry(reference: ImageReference, direct_hosts: str) -> bool:
    """True when the registry is listed as reached without the proxy (a registry on the local network)."""
    listed = {h.strip().lower() for h in direct_hosts.split(",") if h.strip()}
    return reference.registry.lower() in listed or reference.registry_host.lower() in listed


def parse_registry_secret(secret: str) -> tuple[str, str]:
    """``(user, password)`` from ``user:password`` or JSON ``{"username": ..., "password": ...}``."""
    text = secret.strip()
    if text.startswith("{"):
        try:
            data = json.loads(text)
            user, password = str(data["username"]), str(data["password"])
        except (ValueError, KeyError, TypeError) as exc:
            raise SourceError("The stored registry credential is not readable.", code="image.bad_credential") from exc
    else:
        user, _, password = text.partition(":")
    if not user or not password or "\n" in user or "\n" in password:
        raise SourceError("The stored registry credential has no user name or password.", code="image.bad_credential")
    return user, password


def render_auth_file(registry: str, user: str, password: str) -> str:
    """The containers ``auth.json`` for one registry."""
    token = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
    return json.dumps({"auths": {registry: {"auth": token}}})


def explain_skopeo_failure(logs: str, reference: ImageReference) -> str:
    """A plain-language reason for a failed ``skopeo copy`` (never echoes a credential)."""
    text = logs.lower()
    name = reference.name
    if "unauthorized" in text or "authentication required" in text or ("denied" in text and "proxy" not in text):
        return (
            f"The registry refused access to {name}. Check the registry credential of this target "
            "(it may have expired) and that the account may pull this image."
        )
    if "manifest unknown" in text or "name unknown" in text or "not found" in text or "404" in text:
        return f"The image {name} was not found in the registry (check the name and the tag)."
    if "no such host" in text or ("lookup" in text and "failed" in text):
        return f"The registry host {reference.registry_host} could not be found by name."
    if "x509" in text or "certificate" in text:
        return (
            f"The certificate of {reference.registry_host} is not trusted by the image intake. "
            "Use a registry with a certificate from a public or corporate authority the platform trusts."
        )
    if "proxy" in text or "forbidden" in text or "403" in text or "connection refused" in text or "timeout" in text:
        return (
            f"The egress proxy or the network did not let the image intake reach {reference.registry_host}. "
            "The proxy allows ports 80 and 443 only and the registry's own hosts; a registry on another port "
            "or on the local network must be listed in SECURESCAN_IMAGE_REGISTRY_DIRECT_HOSTS."
        )
    return f"Copying the image {name} failed. The details are in the job log."


# --------------------------------------------------------------------------- the archive
@dataclass
class ExtractSummary:
    layers: int = 0
    files: int = 0
    directories: int = 0
    symlinks: int = 0
    hardlinks: int = 0
    bytes: int = 0
    whiteouts: int = 0
    skipped_special: int = 0
    entries: int = 0
    image_id: str | None = None
    repo_tags: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ExtractLimits:
    max_bytes: int = 8 * 1024**3
    max_entries: int = 2_000_000


def _member(outer: tarfile.TarFile, name: str) -> tarfile.TarInfo | None:
    for candidate in (name, "./" + name, name.lstrip("./")):
        try:
            return outer.getmember(candidate)
        except KeyError:
            continue
    return None


def _read_json(outer: tarfile.TarFile, name: str) -> Any:
    member = _member(outer, name)
    if member is None or not member.isfile() or member.size > MAX_MANIFEST_BYTES:
        return None
    handle = outer.extractfile(member)
    if handle is None:
        return None
    try:
        return json.loads(handle.read())
    except ValueError:
        return None


def blob_name(digest: str) -> str:
    algorithm, _, value = digest.partition(":")
    return f"blobs/{algorithm}/{value}"


def layer_list(outer: tarfile.TarFile) -> tuple[list[str], str | None, list[str]]:
    """``(layer member names in order, image id, repo tags)`` from ``manifest.json`` or an OCI layout."""
    manifest = _read_json(outer, "manifest.json")
    if isinstance(manifest, list) and manifest and isinstance(manifest[0], dict):
        entry = manifest[0]
        layers = [str(x) for x in entry.get("Layers") or []]
        config = str(entry.get("Config") or "")
        image_id = config[: -len(".json")] if config.endswith(".json") else (config or None)
        if image_id and image_id.startswith("blobs/"):
            image_id = image_id.split("/", 2)[-1]
        return layers, image_id or None, [str(t) for t in entry.get("RepoTags") or []]
    index = _read_json(outer, "index.json")
    if isinstance(index, dict):
        descriptors = index.get("manifests") or []
        chosen = _pick_manifest(outer, descriptors)
        if chosen is not None:
            config = chosen.get("config") or {}
            layers = [blob_name(str(layer.get("digest"))) for layer in chosen.get("layers") or [] if layer.get("digest")]
            image_id = str(config.get("digest") or "").partition(":")[2] or None
            return layers, image_id, []
    raise SourceError(
        "The image archive is not a docker or OCI image archive (no manifest.json or index.json).",
        code="image.bad_archive",
    )


def _pick_manifest(outer: tarfile.TarFile, descriptors: list[Any], depth: int = 0) -> dict[str, Any] | None:
    """The image manifest of an OCI index: linux/amd64 when the index is a list of platforms, else the first."""
    if depth > 3:
        return None
    candidates = [d for d in descriptors if isinstance(d, dict) and d.get("digest")]
    preferred = [
        d for d in candidates if (d.get("platform") or {}).get("os") == "linux" and (d.get("platform") or {}).get("architecture") == "amd64"
    ]
    for descriptor in [*preferred, *candidates]:
        document = _read_json(outer, blob_name(str(descriptor["digest"])))
        if not isinstance(document, dict):
            continue
        if "layers" in document:
            return document
        if "manifests" in document:
            nested = _pick_manifest(outer, document.get("manifests") or [], depth + 1)
            if nested is not None:
                return nested
    return None


def clean_parts(name: str) -> list[str]:
    """The components of a member name below the image root. ``..`` rejects the image; a leading ``/`` is dropped."""
    if "\x00" in name:
        raise SourceError("The image holds a file name with a NUL character.", code="image.bad_path")
    parts = [part for part in name.replace("\\", "/").split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise SourceError(
            f"The image tries to write outside its own file system ({name[:80]!r}); it was rejected.",
            code="image.path_traversal",
        )
    return parts


class _Extractor:
    """Applies layers to a root directory. One instance per image."""

    def __init__(self, root: Path, limits: ExtractLimits) -> None:
        self.root = root
        self.limits = limits
        self.summary = ExtractSummary()
        self._resolved: dict[tuple[str, ...], tuple[str, ...]] = {}

    # ------------------------------------------------------------------ path handling
    def resolve(self, parts: Sequence[str], *, follow_last: bool = False) -> list[str]:
        """Resolve links in ``parts`` below the root like a chroot (``..`` stops at the root)."""
        key = tuple(parts)
        if follow_last and key in self._resolved:
            return list(self._resolved[key])
        resolved: list[str] = []
        pending = list(parts)
        hops = 0
        while pending:
            part = pending.pop(0)
            if part in ("", "."):
                continue
            if part == "..":
                if resolved:
                    resolved.pop()
                continue
            last = not pending
            candidate = self.root.joinpath(*resolved, part)
            if (not last or follow_last) and os.path.islink(candidate):
                hops += 1
                if hops > MAX_SYMLINK_HOPS:
                    raise SourceError("The image has a loop of symbolic links.", code="image.link_loop")
                target = os.readlink(candidate)
                if target.startswith("/"):
                    resolved = []
                pending = [p for p in target.split("/") if p] + pending
                continue
            resolved.append(part)
        if follow_last:
            self._resolved[key] = tuple(resolved)
        return resolved

    def target_path(self, parts: Sequence[str]) -> Path:
        """The place of a member: its directory resolved through links, then its own name."""
        parent = self.resolve(parts[:-1], follow_last=True)
        return self.root.joinpath(*parent, parts[-1])

    def forget(self) -> None:
        self._resolved.clear()

    # ------------------------------------------------------------------ removing
    def remove(self, path: Path) -> None:
        if os.path.lexists(path):
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path, ignore_errors=True)
            else:
                try:
                    os.unlink(path)
                except OSError:
                    pass
            self.forget()

    def clear_directory(self, path: Path) -> None:
        if os.path.isdir(path) and not os.path.islink(path):
            for child in os.listdir(path):
                self.remove(path / child)

    # ------------------------------------------------------------------ one layer
    def apply_whiteouts(self, layer: tarfile.TarFile) -> None:
        for member in layer:
            parts = clean_parts(member.name)
            if not parts or not parts[-1].startswith(WHITEOUT):
                continue
            name = parts[-1]
            if name == OPAQUE:
                parent = self.resolve(parts[:-1], follow_last=True)
                self.clear_directory(self.root.joinpath(*parent))
                self.summary.whiteouts += 1
            elif name.startswith(WHITEOUT + ".wh."):
                continue  # other .wh..wh.* bookkeeping names
            else:
                hidden = name[len(WHITEOUT) :]
                if not hidden or "/" in hidden:
                    continue
                parent = self.resolve(parts[:-1], follow_last=True)
                self.remove(self.root.joinpath(*parent, hidden))
                self.summary.whiteouts += 1

    def extract_members(self, layer: tarfile.TarFile) -> None:
        for member in layer:
            parts = clean_parts(member.name)
            if not parts or parts[-1].startswith(WHITEOUT):
                continue
            self.summary.entries += 1
            if self.summary.entries > self.limits.max_entries:
                raise SourceError("The image has too many files.", code="image.too_many_entries")
            try:
                self.extract_member(layer, member, parts)
            except OSError as exc:
                raise SourceError(
                    f"The image's file tree is inconsistent at {'/'.join(parts)[:80]!r} ({type(exc).__name__}).",
                    code="image.bad_archive",
                ) from exc

    def extract_member(self, layer: tarfile.TarFile, member: tarfile.TarInfo, parts: list[str]) -> None:
        path = self.target_path(parts)
        if member.isdir():
            if os.path.islink(path) and os.path.isdir(path):
                return  # a directory entry over a link to a directory keeps the link (overlay behaviour)
            if os.path.lexists(path) and not os.path.isdir(path):
                self.remove(path)
            os.makedirs(path, exist_ok=True)
            os.chmod(path, 0o755)
            self.summary.directories += 1
            return
        self.ensure_parent(path)
        if member.isreg():
            self.remove_for_file(path)
            self.write_file(layer, member, path)
        elif member.issym():
            self.remove_for_file(path)
            self.write_symlink(path, parts, member.linkname)
        elif member.islnk():
            self.remove_for_file(path)
            self.write_hardlink(path, member.linkname)
        else:
            self.summary.skipped_special += 1  # devices, fifos, anything else

    def ensure_parent(self, path: Path) -> None:
        parent = path.parent
        if not os.path.isdir(parent):
            if os.path.lexists(parent):
                self.remove(parent)
            os.makedirs(parent, exist_ok=True)
            os.chmod(parent, 0o755)

    def remove_for_file(self, path: Path) -> None:
        if os.path.lexists(path):
            self.remove(path)

    def write_file(self, layer: tarfile.TarFile, member: tarfile.TarInfo, path: Path) -> None:
        source = layer.extractfile(member)
        if source is None:
            return
        written = 0
        with open(path, "xb") as out:
            while True:
                chunk = source.read(CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                self.summary.bytes += len(chunk)
                if self.summary.bytes > self.limits.max_bytes:
                    raise SourceError(
                        "The image is larger than the allowed size once unpacked.", code="image.too_large"
                    )
                out.write(chunk)
        os.chmod(path, 0o755 if member.mode & 0o111 else 0o644)
        self.summary.files += 1

    def write_symlink(self, path: Path, parts: Sequence[str], linkname: str) -> None:
        """A link rewritten to a relative link that stays inside the root (a chroot's view of it)."""
        if "\x00" in linkname:
            self.summary.skipped_special += 1
            return
        directory = self.resolve(parts[:-1], follow_last=True)
        if linkname.startswith("/"):
            segments = [p for p in linkname.split("/") if p]
            base: list[str] = []
        else:
            segments = [p for p in linkname.split("/") if p]
            base = list(directory)
        target: list[str] = list(base)
        for segment in segments:
            if segment == ".":
                continue
            if segment == "..":
                if target:
                    target.pop()
                continue
            target.append(segment)
        relative = posixpath.relpath("/".join(target) or ".", "/".join(directory) or ".")
        os.symlink(relative, path)
        self.summary.symlinks += 1
        self.forget()

    def write_hardlink(self, path: Path, linkname: str) -> None:
        source_parts = clean_parts(linkname)
        if not source_parts:
            self.summary.skipped_special += 1
            return
        source = self.root.joinpath(*self.resolve(source_parts))
        if os.path.islink(source) or not os.path.isfile(source):
            self.summary.skipped_special += 1
            return
        size = os.path.getsize(source)
        self.summary.bytes += size
        if self.summary.bytes > self.limits.max_bytes:
            raise SourceError("The image is larger than the allowed size once unpacked.", code="image.too_large")
        shutil.copyfile(source, path)
        os.chmod(path, os.stat(source).st_mode & 0o755 | 0o644)
        self.summary.hardlinks += 1


def open_layer(outer: tarfile.TarFile, name: str) -> tarfile.TarFile:
    member = _member(outer, name)
    if member is None or not member.isfile():
        raise SourceError(f"The image archive lacks the layer {name[:80]!r}.", code="image.bad_archive")
    handle = outer.extractfile(member)
    if handle is None:
        raise SourceError(f"The layer {name[:80]!r} cannot be read.", code="image.bad_archive")
    try:
        return tarfile.open(fileobj=handle, mode="r|*")
    except tarfile.TarError as exc:
        raise SourceError(f"The layer {name[:80]!r} is not a readable archive.", code="image.bad_archive") from exc


def extract_image_archive(archive: Path, root: Path, limits: ExtractLimits | None = None) -> ExtractSummary:
    """Apply the layers of the image archive to ``root`` (created when missing). See the module docstring."""
    lim = limits or ExtractLimits()
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o755)
    extractor = _Extractor(root, lim)
    try:
        outer = tarfile.open(archive, mode="r:*")
    except (tarfile.TarError, OSError) as exc:
        raise SourceError("The image archive cannot be read as a tar file.", code="image.bad_archive") from exc
    with outer:
        layers, image_id, tags = layer_list(outer)
        extractor.summary.image_id = image_id
        extractor.summary.repo_tags = tags
        if not layers:
            raise SourceError("The image archive lists no layers.", code="image.bad_archive")
        for name in layers:
            try:
                with open_layer(outer, name) as layer:
                    extractor.apply_whiteouts(layer)
                with open_layer(outer, name) as layer:
                    extractor.extract_members(layer)
            except tarfile.TarError as exc:
                raise SourceError(f"The layer {name[:80]!r} is damaged.", code="image.bad_archive") from exc
            extractor.summary.layers += 1
            extractor.forget()
    return extractor.summary


def skipped_for_java(name: str) -> bool:
    lowered = name.lower()
    return lowered in JDK_DIRECTORIES or lowered.startswith(JDK_DIRECTORY_PREFIXES)


def collect_java_archives(src_root: Path, rootfs: Path, limit: int = MAX_JAVA_ARCHIVES) -> list[str]:
    """Paths (relative to ``src_root``) of the ``*.jar``, ``*.war`` and ``*.ear`` files in the extracted image,
    leaving out the Java installation itself. Sorted; at most ``limit``."""
    found: list[str] = []
    for current, dirs, files in os.walk(rootfs, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not skipped_for_java(d) and not os.path.islink(os.path.join(current, d)))
        for name in sorted(files):
            if name.lower().endswith(JAVA_SUFFIXES) and not os.path.islink(os.path.join(current, name)):
                relative = os.path.relpath(os.path.join(current, name), src_root).replace(os.sep, "/")
                found.append(relative)
                if len(found) >= limit:
                    return found
    return found


# --------------------------------------------------------------------------- the source handler
async def _copy_upload(request: SourceRequest, archive: Path) -> str:
    from securescan.db.models.artifacts import Artifact
    from securescan.storage.artifacts import StorageError, artifact_path

    target = request.target
    artifact = await request.session.get(Artifact, target.upload_artifact_id)
    if artifact is None or artifact.deleted_at is not None:
        raise SourceError("The uploaded image archive no longer exists.", code="image.upload_missing")
    try:
        source = artifact_path(artifact)
    except StorageError as exc:
        raise SourceError("The uploaded image archive cannot be found.", code="image.upload_missing") from exc
    if not source.is_file():
        raise SourceError("The uploaded image archive cannot be found.", code="image.upload_missing")
    await asyncio.to_thread(shutil.copyfile, source, archive)
    return str(artifact.filename or "archive")


async def _registry_secret(request: SourceRequest, reference: ImageReference) -> tuple[str, str] | None:
    from securescan.db.models.credentials import Credential
    from securescan.db.models.enums import CredentialKind
    from securescan.domain.credentials import reveal_secret
    from securescan.util import utcnow

    credential_id = request.target.credential_id
    if credential_id is None:
        return None
    credential = await request.session.get(Credential, credential_id)
    if credential is None or credential.revoked_at is not None:
        raise SourceError("The registry credential of this target was revoked or removed.", code="image.credential_missing")
    if credential.kind != CredentialKind.REGISTRY:
        # Defence in depth (the API refuses this too): any other secret would be sent to the registry host of the locator.
        raise SourceError("The credential of this target is not a registry login.", code="image.credential_kind")
    secret = parse_registry_secret(reveal_secret(credential))
    credential.last_used_at = utcnow()
    return secret


async def pull_image(request: SourceRequest, reference: ImageReference, archive: Path) -> None:
    """``skopeo copy`` of the reference into ``archive`` (see the module docstring)."""
    from securescan.runner.catalogue import get_entry, resolve_image_with_override
    from securescan.runner.egress import EgressError, egress_lease
    from securescan.runner.tools._support import write_private_file

    settings = request.settings
    workspace = request.workspace
    entry = get_entry(SKOPEO_TOOL)
    image = await resolve_image_with_override(request.session, entry, settings)
    credential = await _registry_secret(request, reference)
    # No transaction (and no row lock on the credential) is held while the container runs.
    await request.session.commit()
    staging = workspace.out / "tmp"
    staging.mkdir(exist_ok=True)
    os.chmod(staging, 0o777)
    auth_path: Path | None = None
    if credential is not None:
        auth_path = write_private_file(
            workspace.config, AUTH_FILE, render_auth_file(reference.registry, credential[0], credential[1])
        )
    direct = is_direct_registry(reference, settings.image_registry_direct_hosts)
    await request.log(f"copying {reference.name} with skopeo" + (" (direct)" if direct else " through the egress proxy"))
    try:
        if direct:
            result = await _run_skopeo(request, entry, image.reference, reference, "", auth_path)
        else:
            try:
                async with egress_lease(registry_hosts(reference)) as proxy_url:
                    result = await _run_skopeo(request, entry, image.reference, reference, proxy_url, auth_path)
            except EgressError as exc:
                raise SourceError(str(exc), code="image.egress") from exc
    finally:
        if auth_path is not None:
            try:
                auth_path.unlink()
            except OSError:
                pass
    if result.timed_out:
        raise SourceError(
            f"Copying the image did not finish within {int(entry.timeout_seconds // 60)} minutes.",
            code="image.timeout",
        )
    if result.exit_code != 0:
        log.warning("skopeo_failed", exit_code=result.exit_code, tail=scrub(result.logs[-300:]))
        raise SourceError(explain_skopeo_failure(result.logs, reference), code="image.pull_failed")
    produced = workspace.out / ARCHIVE_NAME
    if not produced.is_file():
        raise SourceError("skopeo finished but wrote no image archive.", code="image.pull_failed")
    await asyncio.to_thread(shutil.move, str(produced), str(archive))
    shutil.rmtree(staging, ignore_errors=True)


async def _run_skopeo(
    request: SourceRequest,
    entry: Any,
    image_reference: str,
    reference: ImageReference,
    proxy_url: str,
    auth_path: Path | None,
) -> Any:
    from securescan.runner.launcher import get_launcher
    from securescan.runner.tools._support import egress_network, proxy_env, spec_from_entry
    from securescan.runner.tools.base import LABEL_JOB, LABEL_SCAN

    settings = request.settings
    workspace = request.workspace
    env: dict[str, str] = dict(proxy_env(proxy_url))
    if auth_path is not None:
        env["REGISTRY_AUTH_FILE"] = f"{entry.mount_target('config')}/{AUTH_FILE}"
    spec = spec_from_entry(
        entry,
        image_reference,
        name=f"securescan-job-{workspace.job_id}-skopeo",
        binds=[
            (str(workspace.out), entry.mount_target("out"), False),
            (str(workspace.config), entry.mount_target("config"), True),
        ],
        env=env,
        network=egress_network(settings),
        labels={LABEL_JOB: str(workspace.job_id), LABEL_SCAN: str(request.scan.id)},
        command=entry.render_command({"target_url": reference.docker_url}),
    )
    return await get_launcher().run(spec, entry.timeout_seconds, request.log)


async def acquire_image(request: SourceRequest) -> SourceInfo:
    """Source handler for ``image`` targets."""
    target = request.target
    workspace = request.workspace
    settings = request.settings
    archive = workspace.config / ARCHIVE_NAME
    notes: list[str] = []
    if target.upload_artifact_id is not None:
        label = await _copy_upload(request, archive)
        description = f"uploaded image archive {label}"
        await request.log(f"using the uploaded image archive {label}")
    else:
        reference = parse_image_reference(target.locator or "")
        if reference.tag is None and reference.digest is None:
            notes.append("The image reference has no tag or digest; the registry's default tag was used.")
        await pull_image(request, reference, archive)
        description = f"image {reference.name}"
    os.chmod(archive, 0o644)
    await request.log("unpacking the image file system")
    rootfs = workspace.src / ROOTFS_DIR
    limits = ExtractLimits(max_bytes=settings.image_max_extracted_bytes, max_entries=settings.image_max_entries)
    summary = await asyncio.to_thread(extract_image_archive, archive, rootfs, limits)
    java = await asyncio.to_thread(collect_java_archives, workspace.src, rootfs)
    await request.log(
        f"unpacked {summary.layers} layers: {summary.files} files, {summary.symlinks} links, "
        f"{summary.whiteouts} deletions; {len(java)} Java archive(s)"
    )
    if summary.skipped_special:
        notes.append(f"{summary.skipped_special} device or special file(s) of the image were not unpacked.")
    return SourceInfo(
        kind="image",
        is_git=False,
        description=description,
        notes=notes,
        details={
            "image_id": summary.image_id,
            "repo_tags": summary.repo_tags,
            "layers": summary.layers,
            "files": summary.files,
            "bytes": summary.bytes,
            "java_archives": java,
        },
    )


def register_image_source() -> None:
    """Make ``acquire_image`` the handler of ``image`` targets."""
    register_source_handler("image", acquire_image)
