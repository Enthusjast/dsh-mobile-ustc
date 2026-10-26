#!/usr/bin/env python3
"""Run APK verification and optional installer-consent checks on an owned test AVD.

No candidate APK is installed by these cases. The normal debug app/test APKs are
installed with -r; userdata, device keys and other emulator processes are kept.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zipfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", required=True)
    parser.add_argument("--avd", required=True)
    parser.add_argument("--adb", type=Path)
    parser.add_argument("--prepare-dex", action="store_true", help="Compile app/test dex after installation, for slow software emulators")
    parser.add_argument("--installer-fixture", action="store_true", help="Test encrypted installation records and system consent; never approve the candidate APK")
    parser.add_argument("--log", type=Path, help="Write this run to a distinct log inside the repository's .local directory")
    options = parser.parse_args()
    if not re.fullmatch(r"emulator-[0-9]+", options.serial) or not re.fullmatch(r"dsh-remote-api[0-9]+", options.avd):
        parser.error("an exact task-owned test emulator is required; preview/physical devices are excluded")
    repo = Path(__file__).resolve().parents[2]
    executable = options.adb or repo / ".local/android-sdk/platform-tools/adb"
    adb = [str(executable), "-s", options.serial]

    def call(*args, timeout=30):
        return subprocess.run(adb + list(args), check=True, capture_output=True, text=True, timeout=timeout)

    def owned():
        if call("emu", "avd", "name").stdout.splitlines()[0] != options.avd:
            raise RuntimeError("test emulator ownership changed")

    owned()
    api = int(call("shell", "getprop", "ro.build.version.sdk").stdout.strip())
    if api < 26 or api != int(options.avd.removeprefix("dsh-remote-api")) or call("shell", "getprop", "sys.boot_completed").stdout.strip() != "1":
        raise RuntimeError("the test AVD must be booted on API 26 or newer")
    log = (options.log or repo / f".local/apk-preflight-api{api}-device.log").resolve()
    if not log.is_relative_to((repo / ".local").resolve()):
        raise RuntimeError("test logs must remain under this repository's .local directory")
    app = repo / "android/app/build/outputs/apk/debug/app-debug.apk"
    tests = repo / "android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"
    with zipfile.ZipFile(app) as archive:
        if archive.testzip() is not None or any(name in archive.namelist() for name in ["assets/deployment.json", "assets/push-deployment.json", "assets/app-update-deployment.json"]) or any(name.startswith("assets/apk-updates/") for name in archive.namelist()):
            raise RuntimeError("a complete unconfigured debug app without test APK assets is required")
    with zipfile.ZipFile(tests) as archive:
        if archive.testzip() is not None:
            raise RuntimeError("complete test APK required")
        fixtures = json.loads(archive.read("assets/apk-updates/fixtures.json"))
        if fixtures["v"] != 1 or set(fixtures["fixtures"]) != {"upgrade", "same-version", "downgrade", "wrong-package", "wrong-signer", "higher-sdk", "rotated", "multiple-signers", "tampered", "truncated"}:
            raise RuntimeError("current generated APK fixtures are required")
    print(f"Owned {options.avd} / API {api}; debug APK SHA-256 {hashlib.sha256(app.read_bytes()).hexdigest()}", flush=True)
    for apk in [app, tests]:
        owned(); print(call("install", "-r", "-t", str(apk), timeout=240).stdout.strip(), flush=True)
    if options.prepare_dex:
        for package in ["cn.edu.ustc.dsh.mobile", "cn.edu.ustc.dsh.mobile.test"]:
            owned(); print("Prepare installed dex for " + package, flush=True)
            result = call("shell", "cmd", "package", "compile", "-m", "speed", "-f", package, timeout=600)
            if "Success" not in result.stdout:
                raise RuntimeError("installed-package dex preparation did not succeed")
            print(result.stdout.strip(), flush=True)
    source = repo / "android/app/src/androidTest/kotlin/cn/edu/ustc/dsh/mobile/AndroidApkVerifierTest.kt"
    count = len(re.findall(r"@Test\s+fun\b", source.read_text())) + 1  # actual Hilt startup case
    log.parent.mkdir(exist_ok=True)
    classes = "cn.edu.ustc.dsh.mobile.AndroidApkVerifierTest,cn.edu.ustc.dsh.mobile.MainStartupTest"
    if options.installer_fixture:
        for name in ["AppInstallationStorageTest", "AppInstallationsTest"]:
            source = repo / f"android/app/src/androidTest/kotlin/cn/edu/ustc/dsh/mobile/{name}.kt"
            count += len(re.findall(r"@Test\s+fun\b", source.read_text()))
            classes += ",cn.edu.ustc.dsh.mobile." + name
    owned()
    original_mode = None
    restoration_error = None
    try:
        if options.installer_fixture:
            text = call("shell", "appops", "get", "cn.edu.ustc.dsh.mobile", "REQUEST_INSTALL_PACKAGES").stdout
            match = re.search(r"REQUEST_INSTALL_PACKAGES:\s*(allow|ignore|deny|default|foreground)\b", text)
            if not match and "No operations" not in text:
                raise RuntimeError("cannot preserve original unknown-source app-op: " + text)
            original_mode = match.group(1) if match else "default"
            call("shell", "appops", "set", "cn.edu.ustc.dsh.mobile", "REQUEST_INSTALL_PACKAGES", "allow")
        with log.open("w") as stream:
            result = subprocess.run(adb + ["shell", "am", "instrument", "-w", "-e", "networkFixture", "true", "-e", "installerFixture", str(options.installer_fixture).lower(), "-e", "class", classes,
                                          "cn.edu.ustc.dsh.mobile.test/androidx.test.runner.AndroidJUnitRunner"],
                                    stdout=stream, stderr=subprocess.STDOUT, timeout=600)
    finally:
        if original_mode is not None:
            try:
                owned(); call("shell", "appops", "set", "cn.edu.ustc.dsh.mobile", "REQUEST_INSTALL_PACKAGES", original_mode)
            except (subprocess.SubprocessError, RuntimeError) as error:
                restoration_error = f"restore REQUEST_INSTALL_PACKAGES to {original_mode}: {type(error).__name__}"
    text = log.read_text()
    print(text, flush=True)
    if result.returncode != 0 or f"OK ({count} tests)" not in text or "FAILURES" in text:
        raise RuntimeError("APK platform preflight did not pass; inspect " + str(log) + ("; cleanup required: " + restoration_error if restoration_error else ""))
    if restoration_error:
        raise RuntimeError("APK tests completed but fixture cleanup failed: " + restoration_error)
    print(f"API {api}: {count} APK/startup/installer cases passed; no candidate update installed", flush=True)


if __name__ == "__main__":
    main()
