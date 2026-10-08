"""SpotBugs: class file names, Java artifact discovery, command, skipping without classes, exit codes."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from securescan.db.models.enums import JobState
from securescan.runner.tools import get_builder
from securescan.runner.tools import spotbugs as spotbugs_module
from securescan.runner.tools.base import ToolPreparationError
from securescan.runner.tools.spotbugs import (
    JavaDiscovery,
    SpotBugsBuilder,
    class_root,
    discover_java,
    is_library,
    parse_class_name,
)
from tests.unit.m8_helpers import ctx_for, make_class_file, put_file

BUILDER = SpotBugsBuilder()


def test_registered() -> None:
    assert get_builder("spotbugs") is spotbugs_module.BUILDER


# --------------------------------------------------------------------------- class files
def test_the_class_name_is_read_from_the_constant_pool() -> None:
    assert parse_class_name(make_class_file("com/example/App")) == "com/example/App"
    assert parse_class_name(make_class_file("Top")) == "Top"
    assert parse_class_name(b"not a class file at all") is None
    assert parse_class_name(b"") is None
    assert parse_class_name(make_class_file("a/B")[:20]) is None, "a header cut short is not an error"


def test_the_package_root_comes_from_the_class_name(tmp_path: Path) -> None:
    deep = put_file(tmp_path, "target/classes/com/example/util/U.class", make_class_file("com/example/util/U"))
    assert class_root(deep) == tmp_path / "target" / "classes"
    flat = put_file(tmp_path, "flat/Top.class", make_class_file("Top"))
    assert class_root(flat) == tmp_path / "flat"
    wrong = put_file(tmp_path, "elsewhere/X.class", make_class_file("com/example/X"))
    assert class_root(wrong) is None, "the directory does not match the package"
    junk = put_file(tmp_path, "junk/Y.class", b"junk")
    assert class_root(junk) is None


# --------------------------------------------------------------------------- discovery
def test_library_directories() -> None:
    assert is_library("web/WEB-INF/lib/spring.jar") and is_library("lib/a.jar") and is_library("target/lib/dep.jar")
    assert not is_library("target/app.jar") and not is_library("build/libs/service.jar") and not is_library("app.jar")


def build_tree(root: Path) -> None:
    put_file(root, "target/classes/com/example/App.class", make_class_file("com/example/App"))
    put_file(root, "target/classes/com/example/util/U.class", make_class_file("com/example/util/U"))
    put_file(root, "target/test-classes/com/example/AppTest.class", make_class_file("com/example/AppTest"))
    put_file(root, "target/app-1.0.jar")
    put_file(root, "target/app-1.0-sources.jar")
    put_file(root, "target/lib/dep.jar")
    put_file(root, "web/WEB-INF/lib/spring.jar")
    put_file(root, "web/app.war")
    put_file(root, "build/libs/service.jar")
    put_file(root, "gradle/build/classes/java/main/org/x/G.class", make_class_file("org/x/G"))
    put_file(root, "gradle/build/classes/java/test/org/x/GT.class", make_class_file("org/x/GT"))
    put_file(root, "node_modules/pkg/bad.jar")
    put_file(root, ".git/objects/x.jar")
    put_file(root, "usr/lib/jvm/java-17/lib/rt.jar")
    put_file(root, "opt/openjdk-21/lib/more.jar")
    put_file(root, "empty.jar", b"")
    put_file(root, "flat/Top.class", make_class_file("Top"))


def test_discovery_finds_the_application_and_separates_the_libraries(tmp_path: Path) -> None:
    build_tree(tmp_path)
    found = discover_java(tmp_path)
    assert found.archives == ["build/libs/service.jar", "target/app-1.0.jar", "web/app.war"]
    assert found.libraries == ["target/lib/dep.jar", "web/WEB-INF/lib/spring.jar"]
    # target/classes sits beside the JAR built from it and is left out; test classes are left out
    assert found.class_dirs == ["flat", "gradle/build/classes/java/main"]
    assert found.truncated is False and found.targets == [*found.archives, *found.class_dirs]


def test_discovery_of_a_class_tree_at_the_root(tmp_path: Path) -> None:
    put_file(tmp_path, "com/example/App.class", make_class_file("com/example/App"))
    assert discover_java(tmp_path).class_dirs == ["."]


def test_a_source_with_only_libraries_has_nothing_to_analyse(tmp_path: Path) -> None:
    put_file(tmp_path, "lib/a.jar")
    found = discover_java(tmp_path)
    assert found.targets == [] and found.libraries == ["lib/a.jar"]
    assert JavaDiscovery().targets == []


def test_discovery_never_follows_links(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    put_file(outside, "secret.jar")
    source = tmp_path / "src"
    source.mkdir()
    try:
        (source / "link").symlink_to(outside, target_is_directory=True)
        (source / "file.jar").symlink_to(outside / "secret.jar")
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are not available here")
    assert discover_java(source).targets == []


@pytest.mark.skipif(os.name == "nt", reason="a backslash is a path separator on Windows")
def test_file_names_with_backslashes_are_left_out(tmp_path: Path) -> None:
    put_file(tmp_path, "odd\\name.jar")
    put_file(tmp_path, "good.jar")
    assert discover_java(tmp_path).archives == ["good.jar"]


# --------------------------------------------------------------------------- applicability
async def test_a_source_without_classes_is_skipped_with_a_coverage_note(tmp_path: Path) -> None:
    from securescan.runner.executor import _Finish

    ctx = ctx_for("spotbugs")
    put_file(ctx.workspace.src, "src/main/java/App.java", b"class App {}")
    with pytest.raises(_Finish) as info:
        await BUILDER.prepare(ctx)
    assert info.value.skipped is True and info.value.state == JobState.COMPLETED
    assert "no compiled classes found" in (info.value.reason or "")


async def test_prepare_records_what_it_found_and_the_command_lists_it() -> None:
    ctx = ctx_for("spotbugs")
    build_tree(ctx.workspace.src)
    await BUILDER.prepare(ctx)
    assert any("3 archive(s) and 2 class directories with 2 libraries" in note for note in ctx.coverage_notes)
    command = BUILDER.build_command(ctx)
    plan = (
        "-textui -pluginList /opt/findsecbugs/findsecbugs-plugin.jar -effort:max -low -maxHeap 2048 "
        "-xml:withMessages=/out/spotbugs.xml"
    ).split()
    assert command[: len(plan)] == plan
    rest = command[len(plan) :]
    assert rest[0] == "-auxclasspath" and rest[1] == "/src/target/lib/dep.jar:/src/web/WEB-INF/lib/spring.jar"
    assert rest[2:] == [
        "/src/build/libs/service.jar", "/src/target/app-1.0.jar", "/src/web/app.war",
        "/src/flat", "/src/gradle/build/classes/java/main",
    ]  # fmt: skip
    assert all(part.startswith("/src") for part in rest[2:]), "every analysed path lies under /src"


def test_a_very_long_library_list_is_cut_and_noted() -> None:
    ctx = ctx_for("spotbugs")
    libraries = ["lib/" + "x" * 90 + str(i) + ".jar" for i in range(60)]
    ctx.options["java_discovery"] = {"archives": ["app.jar"], "class_dirs": [], "libraries": libraries}
    command = BUILDER.build_command(ctx)
    aux = command[command.index("-auxclasspath") + 1]
    assert len(aux) <= 2000 and command[-1] == "/src/app.jar"
    assert any("left off the class path" in note for note in ctx.coverage_notes)


def test_command_without_discovery_or_targets_is_refused() -> None:
    ctx = ctx_for("spotbugs")
    with pytest.raises(ToolPreparationError):
        BUILDER.build_command(ctx)
    ctx.options["java_discovery"] = {"archives": [], "class_dirs": [], "libraries": ["lib/a.jar"]}
    with pytest.raises(ToolPreparationError):
        BUILDER.build_command(ctx)


def test_a_path_that_climbs_out_of_src_is_refused() -> None:
    from securescan.runner.catalogue import OptionalArgError

    ctx = ctx_for("spotbugs")
    ctx.options["java_discovery"] = {"archives": ["../etc/evil.jar"], "class_dirs": [], "libraries": []}
    with pytest.raises(OptionalArgError):
        BUILDER.build_command(ctx)


# --------------------------------------------------------------------------- container and exit codes
def test_container_has_no_network_a_read_only_source_and_the_image_entrypoint() -> None:
    ctx = ctx_for("spotbugs")
    ctx.options["java_discovery"] = {"archives": ["app.jar"], "class_dirs": [], "libraries": []}
    spec = BUILDER.container_spec(ctx)
    assert spec.network == "none" and spec.read_only_rootfs is True and spec.user == "1000:1000"
    assert spec.entrypoint is None, "the image's ENTRYPOINT is the spotbugs launcher"
    assert [ro for _s, target, ro in spec.binds if target == "/src"] == [True]
    assert [ro for _s, target, ro in spec.binds if target == "/out"] == [False]
    assert spec.env["HOME"] == "/tmp"


def test_exit_codes() -> None:
    ctx = ctx_for("spotbugs")
    assert BUILDER.classify_exit(ctx, 0) == "completed"
    for code in (1, 2, 137, None):
        assert BUILDER.classify_exit(ctx, code) == "failed", code


def test_applicable_for_every_code_target() -> None:
    from securescan.db.models.enums import TargetKind

    for kind in (TargetKind.ZIP, TargetKind.GITHUB_REPO, TargetKind.VENDOR_REPO, TargetKind.IMAGE):
        assert BUILDER.applicable(ctx_for("spotbugs", kind=kind))[0] is True
    assert BUILDER.applicable(ctx_for("spotbugs", kind=TargetKind.URL))[0] is False

