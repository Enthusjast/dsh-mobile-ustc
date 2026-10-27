#!/usr/bin/env python3
"""Build a full, executable debug v2 APK in isolated outputs; never deploy it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import zipfile


PACKAGE = "cn.edu.ustc.dsh.mobile"


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def inspect_apk(path, sdk, version, version_name):
    tools = sdk / "build-tools/35.0.0"
    badging = subprocess.run([str(tools / "aapt2"), "dump", "badging", str(path)], check=True, capture_output=True, text=True).stdout
    line = badging.splitlines()[0]
    fields = dict(re.findall(r"(\w+)='([^']*)'", line))
    if fields.get("name") != PACKAGE or fields.get("versionCode") != str(version) or fields.get("versionName") != version_name:
        raise RuntimeError("unexpected application identity in " + str(path))
    if not re.search(r"^(?:minSdkVersion|sdkVersion):'26'$", badging, re.MULTILINE) or "targetSdkVersion:'36'" not in badging or "application-debuggable" not in badging or "application-testOnly" in badging:
        raise RuntimeError("expected a complete ordinary debuggable API 26–36 application")
    manifest = subprocess.run([str(tools / "aapt2"), "dump", "xmltree", str(path), "--file", "AndroidManifest.xml"], check=True, capture_output=True, text=True).stdout
    if ":testOnly(" in manifest or ":hasCode(" in manifest and re.search(r":hasCode\([^\n]*=false", manifest):
        raise RuntimeError("test-only or non-executable manifest is not an upgrade fixture")
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if archive.testzip() is not None or any(name in names for name in ["assets/deployment.json", "assets/push-deployment.json", "assets/app-update-deployment.json"]) or any(name.startswith("assets/apk-updates/") for name in names):
            raise RuntimeError("invalid archive or unexpected deployment/test assets")
        dex = [name for name in names if re.fullmatch(r"classes(?:[2-9]|[1-9][0-9]+)?\.dex", name)]
        if "classes.dex" not in dex:
            raise RuntimeError("the candidate must contain executable application code")
        required = {b"Lcn/edu/ustc/dsh/mobile/" + name + b";" for name in [b"MainActivity", b"DshApplication", b"LoginController", b"AppInstallations"]}
        for name in dex:
            content = archive.read(name)
            required = {descriptor for descriptor in required if descriptor not in content}
        if required:
            raise RuntimeError("full application components missing from candidate DEX")
    verified = subprocess.run([str(tools / "apksigner"), "verify", "--verbose", "--print-certs", "--min-sdk-version", "26", "--max-sdk-version", "36", str(path)], check=True, capture_output=True, text=True).stdout
    certificates = re.findall(r"Signer #[0-9]+ certificate SHA-256 digest: ([0-9a-f]{64})", verified)
    if len(certificates) != 1:
        raise RuntimeError("exactly one verified current debug signer is required")
    return {"package_name": PACKAGE, "version_code": version, "version_name": version_name, "size_bytes": path.stat().st_size, "sha256": digest(path), "signing_cert_sha256": certificates[0]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True, help="Fresh task-owned output directory inside repository .local")
    parser.add_argument("--sdk", type=Path)
    options = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    local = (repo / ".local").resolve()
    output = options.output.resolve()
    if output == local or not output.is_relative_to(local):
        parser.error("output must be a directory strictly inside this repository's .local")
    sdk = (options.sdk or local / "android-sdk").resolve()
    baseline = repo / "android/app/build/outputs/apk/debug/app-debug.apk"
    test_apk = repo / "android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"
    before = inspect_apk(baseline, sdk, 1, "0.1.0-dev")
    test_hash = digest(test_apk) if test_apk.exists() else None
    output.mkdir(parents=True)
    artifacts = output / "artifacts"
    artifacts.mkdir()
    retained_baseline = artifacts / "app-full-v1.apk"
    shutil.copyfile(baseline, retained_baseline)
    if digest(retained_baseline) != before["sha256"]:
        raise RuntimeError("retained baseline differs from verified ordinary build output")
    log = output / "build.log"
    environment = os.environ.copy()
    environment.update(ANDROID_HOME=str(sdk), ANDROID_SDK_ROOT=str(sdk))
    command = [str(repo / "android/gradlew"), "--no-daemon", "--max-workers=1", "--console=plain", "-Pkotlin.compiler.execution.strategy=in-process",
               "-I", str(repo / "tools/integration/app_upgrade_fixture.init.gradle"), "-PappUpgradeOutput=" + str(output / "builds"), ":app:assembleDebug"]
    try:
        with log.open("w") as stream:
            result = subprocess.run(command, cwd=repo / "android", env=environment, stdout=stream, stderr=subprocess.STDOUT)
        if result.returncode != 0:
            raise RuntimeError("fixture build failed; inspect " + str(log))
        built = output / "builds/app/outputs/apk/debug/app-debug.apk"
        after = inspect_apk(built, sdk, 2, "0.2.0-upgrade-fixture")
        if before["signing_cert_sha256"] != after["signing_cert_sha256"]:
            raise RuntimeError("candidate signer differs from the installed-fixture baseline")
        # Switching the same Gradle project back to its normal build directory
        # can delete previous task outputs as stale. Retain the verified artifact
        # outside all Gradle-owned output paths before any later normal build.
        candidate = artifacts / "app-full-v2.apk"
        shutil.copyfile(built, candidate)
        if digest(candidate) != after["sha256"]:
            raise RuntimeError("retained candidate differs from verified build output")
        revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=repo, check=True, capture_output=True, text=True).stdout.splitlines()
        receipt = {"v": 1, "kind": "full-executable-app-upgrade-fixture", "source_revision": revision,
                   "source_dirty_files": [line[3:] for line in dirty if line[3:] != "PLAN.md"],
                   "baseline": {"path": str(retained_baseline), **before}, "candidate": {"path": str(candidate), **after},
                   "minimum_android_api": 26, "target_android_api": 36, "production_signing": False}
        receipt_path = output / "fixture.json"
        receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
        receipt_path.chmod(0o600)
        print("Full executable version-2 debug fixture: " + str(receipt_path), flush=True)
        print("Candidate SHA-256: " + after["sha256"], flush=True)
    finally:
        if digest(baseline) != before["sha256"] or test_hash is not None and digest(test_apk) != test_hash:
            raise RuntimeError("normal watched app/test APK changed during isolated fixture build")


if __name__ == "__main__":
    main()
