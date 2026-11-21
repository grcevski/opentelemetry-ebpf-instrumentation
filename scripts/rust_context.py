# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Shared release fixture construction for Rust offsets and integration tests."""

import json
import fcntl
import hashlib
import os
from contextlib import contextmanager
from pathlib import Path
import shutil
import subprocess
import tempfile


REPO = Path(__file__).resolve().parent.parent
VERSIONS = REPO / "configs/offsets/rust_versions.json"
DEPENDENCIES = REPO / "configs/offsets/rust_dependencies.json"
FIXTURE = REPO / "internal/test/integration/components/rustcontext"


def load_versions():
    return json.loads(VERSIONS.read_text())


def prepare(case, project):
    project.mkdir(parents=True, exist_ok=True)
    shutil.copytree(FIXTURE / "src", project / "src", dirs_exist_ok=True)
    manifest = (FIXTURE / "Cargo.toml").read_text()
    manifest = manifest.replace("=1.54.1", "=" + case["tokio"])
    manifest = manifest.replace("=0.13.5", "=" + case["reqwest"])
    hyper = 'hyper = { version = "=1.12.0", features = ["client", "http1"] }'
    manifest = manifest.replace(hyper, hyper.replace("1.12.0", case["hyper"]) if case["hyper"] else "")
    if case["reqwest"].startswith("0.10."):
        manifest = manifest.replace("[dependencies]", '[dependencies]\ntokio02 = { package = "tokio", version = "=0.2.25", features = ["full"] }')
    path = project / "Cargo.toml"
    if not path.exists() or path.read_text() != manifest:
        path.write_text(manifest)
        (project / "Cargo.lock").unlink(missing_ok=True)
    return path


def prepare_dependencies(case, project, toolchain, offline=False, refresh_lock=False, update_snapshot=False):
    manifest = prepare(case, project)
    snapshots = json.loads(DEPENDENCIES.read_text()) if DEPENDENCIES.exists() else {}
    lock = project / "Cargo.lock"
    recorded = snapshots.get(case["name"])
    manifest_hash = hashlib.sha256(manifest.read_bytes()).hexdigest()
    matches = recorded is not None and recorded["manifest"] == manifest_hash
    if refresh_lock or not matches and update_snapshot:
        lock.unlink(missing_ok=True)
        command = ["cargo", "+"+toolchain, "generate-lockfile", "--manifest-path", str(manifest)]
        if offline:
            command.append("--offline")
        subprocess.run(command, cwd=REPO, check=True)
        snapshots[case["name"]] = {"manifest": manifest_hash, "lock": lock.read_text().splitlines()}
        temporary = DEPENDENCIES.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(snapshots, indent=2, sort_keys=True) + "\n")
        temporary.replace(DEPENDENCIES)
    elif not matches:
        raise ValueError(f"Missing or stale dependency snapshot for {case['name']}; run make update-rust-offsets")
    else:
        lock.write_text("\n".join(recorded["lock"]) + "\n")
    return manifest


@contextmanager
def build_lock(work):
    lock = work / "target" / ".obi-rust-build.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    with lock.open("a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        yield


def build(case, work, toolchain, target=None, offsets=False, offline=False, refresh_lock=False):
    with build_lock(work):
        return build_unlocked(case, work, toolchain, target, offsets, offline, refresh_lock)


def build_unlocked(case, work, toolchain, target=None, offsets=False, offline=False, refresh_lock=False):
    if target is None:
        target = "aarch64-unknown-linux-gnu" if os.uname().machine in ("aarch64", "arm64") else "x86_64-unknown-linux-gnu"
    project = work / toolchain / case["name"]
    manifest = prepare_dependencies(case, project, toolchain, offline, refresh_lock)
    command = ["cargo", "+" + toolchain, "build", "--manifest-path", str(manifest),
               "--target-dir", str(work / "target"), "--locked"]
    if case["features"]:
        command.append("--features=" + case["features"])
    if target:
        command.append("--target=" + target)
    if offline:
        command.append("--offline")
    if not offsets:
        command.append("--release")
    env = dict(os.environ)
    if target == "aarch64-unknown-linux-gnu" and os.uname().machine != "aarch64":
        env.setdefault("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER", "aarch64-linux-gnu-gcc")
        env.setdefault("CC_aarch64_unknown_linux_gnu", "aarch64-linux-gnu-gcc")
    subprocess.run(command, cwd=REPO, env=env, check=True)
    output = work / "target"
    if target:
        output /= target
    output /= "debug" if offsets else "release"
    output /= "rustcontext"
    binary = project / target / ("offsets" if offsets else "release") / "rustcontext"
    binary.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".rustcontext-", dir=binary.parent)
    os.close(descriptor)
    try:
        shutil.copy2(output, temporary)
        os.replace(temporary, binary)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return binary


def scenarios(cases):
    for case in cases:
        yield case["name"], case["name"], case["env"]
    names = {case["name"] for case in cases}
    for name in ("latest", "reqwest-0.12", "reqwest-0.11", "reqwest-0.10"):
        if name in names:
            yield name + "-socket-http1", name, {"INJECT": "1", "NO_USER_WRITE": "1"}
    if "latest" in names:
        yield "latest-owned-http1", "latest", {"INJECT": "1"}
        yield "latest-grouped-worker", "latest", {"INJECT": "1", "SHARED_EXECUTABLE": "1"}
        yield "latest-split-http1", "latest", {"INJECT": "1", "SPLIT_HEADER": "1"}
        yield "latest-forwarded-http1", "latest", {"INJECT": "1", "APP_HEADER": "1", "FORWARDED_APP_HEADER": "1"}
        yield "latest-forwarded-http1-large", "latest", {"INJECT": "1", "APP_HEADER": "1", "FORWARDED_APP_HEADER": "1", "HEADER_PADDING": "8192"}
        yield "latest-forwarded-http1-socket", "latest", {"INJECT": "1", "APP_HEADER": "1", "FORWARDED_APP_HEADER": "1", "NO_USER_WRITE": "1"}
        yield "latest-forwarded-http1-socket-unsampled", "latest", {"INJECT": "1", "APP_HEADER": "1", "FORWARDED_APP_HEADER": "1", "NO_USER_WRITE": "1", "SAMPLER": "always_off", "EXPECTED_SAMPLED": "0"}
        yield "latest-http1-otel-exporter", "latest", {"INJECT": "1", "OTEL_EXPORTER": "1"}
        yield "latest-http1-otel-exporter-app-header", "latest", {"INJECT": "1", "OTEL_EXPORTER": "1", "APP_HEADER": "1", "FORWARDED_APP_HEADER": "1"}
