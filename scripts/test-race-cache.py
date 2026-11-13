#!/usr/bin/env python3
"""Local #2131 workflow policy and Bash consumer checks (requires PyYAML)."""

import argparse
import copy
import os
from pathlib import Path
import subprocess
import tempfile

import yaml


# BaseLoader keeps GitHub's `on` key and scalar values independent of YAML 1.1.
def load(path):
    return yaml.load(Path(path).read_text(), Loader=yaml.BaseLoader)


CACHE_ACTION = "actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"
GO_VERSION = "1.27.4"
GO_BUILDER = f"golang:{GO_VERSION}-alpine3.24@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf"
PREFIX = (
    "race-test-v1-${{ runner.os }}-${{ runner.arch }}-"
    "${{ matrix.platform }}-go${{ matrix.go-version }}-"
)
KEY = PREFIX + "${{ hashFiles('go.mod', 'go.sum') }}"
PATHS = "${{ steps.race-cache-paths.outputs.gomodcache }}\n${{ steps.race-cache-paths.outputs.gocache }}\n"


def expected_workflow(baseline):
    # Separately approved security prerequisite: change only existing Go pins.
    expected = copy.deepcopy(baseline)
    for job in expected["jobs"].values():
        matrix = job.get("strategy", {}).get("matrix", {})
        if "go-version" in matrix:
            matrix["go-version"] = [GO_VERSION]
        for step in job.get("steps", []):
            if step.get("uses") == "actions/setup-go@v7":
                step["with"]["go-version"] = GO_VERSION
    return expected


def toolchain_probes(root):
    assert f"\ngo {GO_VERSION}\n" in (root / "go.mod").read_text(), "module must require the fixed toolchain"
    for name in ("Dockerfile.self-contained", "Dockerfile.dev-self-contained"):
        assert f"FROM --platform=$BUILDPLATFORM {GO_BUILDER} AS builder" in (root / "dockerfiles" / name).read_text().splitlines(), "source builders must use the verified patched Go tag and digest"
    for name in ("pull-request.yml", "release.yml", "release-dev.yaml", "publish-docs.yml"):
        workflow = load(root / ".github/workflows" / name)
        for job in workflow["jobs"].values():
            for step in job.get("steps", []):
                if step.get("uses") == "actions/setup-go@v7":
                    assert step["with"]["go-version"] == GO_VERSION, "CI Go pin must match the fixed compiler"
    assert load(root / ".circleci/config.yml")["jobs"]["build"]["docker"] == [{"image": f"cimg/go:{GO_VERSION}"}], "CircleCI image must use the verified patched Go tag"
    print("PASS fixed module/CI/Docker builder toolchain pins")


def check(workflow, baseline, metadata):
    steps = workflow["jobs"]["test"]["steps"]
    caches = [s for s in steps if s.get("uses", "").startswith("actions/cache@")]
    assert len(caches) == 1, "test job must own exactly one explicit race cache"
    cache = caches[0]
    assert cache["uses"] == CACHE_ACTION, "cache action must match verified immutable release"
    assert set(cache) == {"name", "uses", "with"}, "cache must not gate execution or add env/credentials"
    assert cache["with"] == {"path": PATHS, "key": KEY, "restore-keys": PREFIX + "\n"}, "cache paths/keys must isolate version, platform, architecture and race mode"
    assert set(cache["with"]) <= set(metadata["inputs"]), "unrecognized action input"
    assert metadata["runs"] == {
        "using": "node24", "main": "dist/restore/index.js",
        "post": "dist/save/index.js", "post-if": "success()",
    }, "unexpected pinned action runtime/entrypoints"
    paths = [s for s in steps if s.get("id") == "race-cache-paths"]
    assert len(paths) == 1, "cache paths must be discovered after setup-go"
    paths = paths[0]
    assert set(paths) == {"name", "id", "shell", "run"}, "unexpected cache discovery behavior"
    assert paths["shell"] == "bash", "cache discovery must use portable explicit Bash"
    assert "${{" not in paths["run"], "no expression interpolation into shell source"
    setup = next(s for s in steps if s.get("uses") == "actions/setup-go@v7")
    assert workflow["jobs"]["test"]["strategy"]["matrix"]["go-version"] == [setup["with"]["go-version"]], "cache matrix version must match the installed pinned toolchain"
    assert setup["with"]["cache"] == "false", "avoid duplicate setup-go cache ownership"
    tests = next(s for s in steps if s.get("name") == "Run tests")
    assert steps.index(setup) < steps.index(paths) < steps.index(cache) < steps.index(tests), "cache must precede unconditional tests"

    # Only the two cache steps, ownership flag and approved Go pins may change.
    normalized = copy.deepcopy(workflow)
    normalized_steps = normalized["jobs"]["test"]["steps"]
    normalized_steps[:] = [s for s in normalized_steps if s != paths and s != cache]
    next(s for s in normalized_steps if s.get("uses") == "actions/setup-go@v7")["with"].pop("cache")
    assert normalized == expected_workflow(baseline), "existing jobs, tests, integration, coverage, triggers and permissions must be preserved apart from approved Go pins"
    return paths["run"]


def negative_probes(workflow, baseline, metadata):
    def missing(w):
        steps = w["jobs"]["test"]["steps"]
        steps[:] = [s for s in steps if not s.get("uses", "").startswith("actions/cache@")]

    def cache_input(w, name, value):
        cache = next(s for s in w["jobs"]["test"]["steps"] if s.get("uses") == CACHE_ACTION)
        cache["with"][name] = value

    def duplicate_ownership(w):
        next(s for s in w["jobs"]["test"]["steps"] if s.get("uses") == "actions/setup-go@v7")["with"]["cache"] = "true"

    def skip_tests(w):
        next(s for s in w["jobs"]["test"]["steps"] if s.get("name") == "Run tests")["if"] = "steps.cache.outputs.cache-hit != 'true'"

    def publication_trigger(w):
        w["on"]["push"] = {"branches": ["main"]}

    for name, mutate in (
        ("missing-cache", missing),
        ("cross-mode-restore", lambda w: cache_input(w, "restore-keys", "race-test-\n")),
        ("missing-architecture", lambda w: cache_input(w, "key", KEY.replace("${{ runner.arch }}-", ""))),
        ("per-commit-rotation", lambda w: cache_input(w, "key", KEY + "-${{ github.sha }}")),
        ("missing-build-cache", lambda w: cache_input(w, "path", PATHS.splitlines()[0] + "\n")),
        ("duplicate-cache-ownership", duplicate_ownership),
        ("cache-hit-skips-tests", skip_tests),
        ("changed-publication-trigger", publication_trigger),
    ):
        candidate = copy.deepcopy(workflow)
        mutate(candidate)
        try:
            check(candidate, baseline, metadata)
        except AssertionError as error:
            print(f"REJECT {name}: {error}")
        else:
            raise AssertionError(f"mutation survived: {name}")


def bash_probes(script):
    # Execute the YAML's actual shell, not a Python reimplementation. A tiny go
    # process supplies controlled stdout to exercise Windows paths and bad data.
    with tempfile.TemporaryDirectory(prefix="race-cache-", dir=os.environ.get("TMPDIR")) as tmp:
        root = Path(tmp)
        go = root / "go"
        go.write_text('''#!/bin/bash
case "$*" in
  'env GOMODCACHE') printf '%s\\n' "$PROBE_MOD" ;;
  'env GOCACHE') printf '%s\\n' "$PROBE_BUILD" ;;
  *) exit 8 ;;
esac
exit "${PROBE_STATUS:-0}"
''')
        go.chmod(0o755)
        subprocess.run(["bash", "-n"], input=script, text=True, check=True)
        cases = [
            ("linux", "/home/runner/go/pkg/mod", "/home/runner/.cache/go-build", True),
            ("macos-spaces", "/Users/runner/go/pkg/mod", "/Users/runner/Library/Caches/Go Build", True),
            ("windows-crlf", "C:\\Users\\Runner Name\\go\\pkg\\mod\r", "C:\\Users\\Runner Name\\AppData\\Local\\go-build\r", True),
            ("literal-shell-data", "/cache/$(touch PWNED)", "/cache/quoted ' data", True),
            ("newline-injection", "/cache/mod\ninjected=value", "/cache/build", False),
            ("embedded-cr", "/cache/mo\rd", "/cache/build", False),
            ("empty-output", "", "/cache/build", False),
            ("relative-path", "relative/cache", "/cache/build", False),
            ("bad-second-path", "/cache/mod", "", False),
            ("go-error", "/cache/mod", "/cache/build", False),
        ]
        for name, mod, build, success in cases:
            output = root / "github-output"
            output.write_text("")
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                       GITHUB_OUTPUT=str(output), PROBE_MOD=mod, PROBE_BUILD=build,
                       PROBE_STATUS="7" if name == "go-error" else "0")
            result = subprocess.run(["bash", "--noprofile", "--norc", "-euo", "pipefail", "-c", script],
                                    cwd=root, env=env, text=True, capture_output=True)
            assert (result.returncode == 0) == success, (name, result.stderr)
            expected = f"gomodcache={mod.removesuffix(chr(13))}\ngocache={build.removesuffix(chr(13))}\n" if success else ""
            assert output.read_text() == expected, (name, output.read_text())
            assert not (root / "PWNED").exists(), "shell data was executed"
            print(f"PASS bash/{name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflow", type=Path, default=Path(__file__).resolve().parents[1] / ".github/workflows/pull-request.yml")
    parser.add_argument("--baseline", type=Path, required=True, help="original workflow from the reviewed base revision")
    parser.add_argument("--action-metadata", type=Path, required=True, help="action.yml fetched from the pinned actions/cache SHA")
    args = parser.parse_args()
    workflow, baseline, metadata = load(args.workflow), load(args.baseline), load(args.action_metadata)
    toolchain_probes(Path(__file__).resolve().parents[1])
    script = check(workflow, baseline, metadata)
    print("PASS parsed workflow policy and pinned action input/runtime contract")
    negative_probes(workflow, baseline, metadata)
    bash_probes(script)


if __name__ == "__main__":
    main()
