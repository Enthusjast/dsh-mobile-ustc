#!/usr/bin/env python3
"""Two-phase owned-AVD self-upgrade; target APK is approved by scoped native UI automation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import time
import uuid
from urllib.parse import urlparse
from build_app_upgrade_fixture import inspect_apk


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", required=True)
    parser.add_argument("--avd", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    options = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    cluster = Path(os.environ["REMOTE_TEST_CLUSTER_ROOT"]).resolve()
    if not re.fullmatch(r"emulator-[0-9]+", options.serial) or not re.fullmatch(r"dsh-remote-api(?:26|36)", options.avd):
        parser.error("exact dedicated test AVD required; preview/physical devices excluded")
    source, result = options.input.resolve(), options.result.resolve()
    if not source.is_relative_to(cluster) or not result.is_relative_to(cluster) or source.stat().st_mode & 0o077:
        raise RuntimeError("protected private-cluster input and result required")
    receipt = json.loads(options.receipt.read_text())
    if receipt["v"] != 1 or receipt["kind"] != "full-executable-app-upgrade-fixture" or receipt["candidate"]["version_code"] != 2:
        raise RuntimeError("full executable v2 receipt required")
    sdk = (repo / ".local/android-sdk").resolve()
    for key, code, name in [("baseline", 1, "0.1.0-dev"), ("candidate", 2, "0.2.0-upgrade-fixture")]:
        path = Path(receipt[key]["path"]).resolve()
        if key == "candidate" and not path.is_relative_to((repo / ".local").resolve()):
            raise RuntimeError("candidate must be an isolated local build")
        actual = inspect_apk(path, sdk, code, name)
        if any(actual[field] != receipt[key][field] for field in actual):
            raise RuntimeError("artifact bytes changed")
    if receipt["baseline"]["signing_cert_sha256"] != receipt["candidate"]["signing_cert_sha256"]:
        raise RuntimeError("same signer required")
    data = json.loads(source.read_text()); run = str(uuid.uuid4()); data["run_id"] = run
    origin = urlparse(data["deployment"]["remote_origin"])
    if origin.scheme != "https" or origin.hostname not in {"127.0.0.1", "localhost", "::1"} or not origin.port or origin.username or origin.password or origin.query or origin.fragment:
        raise RuntimeError("explicit host loopback HTTPS fixture required")
    package = "cn.edu.ustc.dsh.mobile"
    if data["candidate_sha256"] != receipt["candidate"]["sha256"] or data["signing_cert_sha256"] != receipt["candidate"]["signing_cert_sha256"]:
        raise RuntimeError("host publication differs from verified full executable fixture")
    adb = [os.environ["REMOTE_TEST_ADB"], "-s", options.serial]
    def call(*args, timeout=30, **kwargs):
        return subprocess.run(adb + list(args), check=True, timeout=timeout, **kwargs)
    def output(*args, timeout=30):
        return call(*args, timeout=timeout, capture_output=True, text=True).stdout
    def owned():
        if output("emu", "avd", "name").splitlines()[0] != options.avd:
            raise RuntimeError("test AVD identity changed")
    def version():
        match = re.search(r"\bversionCode=([0-9]+)", output("shell", "dumpsys", "package", package))
        return int(match.group(1)) if match else None
    def device_json(name):
        return json.loads(output("shell", "run-as", package, "cat", directory + "/" + name))
    owned()
    if version() not in {None, 1}:
        raise RuntimeError("dedicated device must be on ordinary baseline v1; never silently downgrade or wipe")
    directory = "no_backup/app-self-upgrade/" + run
    mode = None; reversed_port = False; process = None
    stopped = False
    def stop(*_):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, stop); signal.signal(signal.SIGINT, stop)
    try:
        for path in [receipt["baseline"]["path"], str(repo / "android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk")]:
            owned(); print(output("install", "-r", "-t", path, timeout=240).strip(), flush=True)
        for name in [package, package + ".test"]:
            print("Prepare dex " + name, flush=True)
            if "Success" not in output("shell", "cmd", "package", "compile", "-m", "speed", "-f", name, timeout=600):
                raise RuntimeError("baseline dex preparation failed")
        prior = output("shell", "appops", "get", package, "REQUEST_INSTALL_PACKAGES")
        match = re.search(r"REQUEST_INSTALL_PACKAGES:\s*(allow|ignore|deny|default|foreground)\b", prior)
        if not match and "No operations" not in prior: raise RuntimeError("cannot preserve source permission")
        mode = match.group(1) if match else "default"
        # Normal source settings UI grants it during the native pre-phase.
        call("shell", "appops", "set", package, "REQUEST_INSTALL_PACKAGES", "default", stdout=subprocess.DEVNULL)
        port = "tcp:" + str(origin.port)
        if any(port in line.split() for line in output("reverse", "--list").splitlines()):
            raise RuntimeError("fixture reverse port already in use")
        call("reverse", port, port, stdout=subprocess.DEVNULL); reversed_port = True
        call("shell", "run-as", package, "mkdir", "-p", directory, stdout=subprocess.DEVNULL)
        command = "umask 077; cat > " + directory + "/input.json"
        call("shell", "run-as", package, "sh", "-c", shlex.quote(command), input=json.dumps(data).encode(), stdout=subprocess.DEVNULL)
        prelog = source.parent / "pre-upgrade.log"
        with prelog.open("w") as stream:
            process = subprocess.Popen(adb + ["shell", "am", "instrument", "-w", "-e", "appSelfUpgrade", "true", "-e", "appSelfUpgradeRun", run,
                "-e", "class", package + ".AppSelfUpgradeTest#prepareAndWaitForRealSystemUpgrade", package + ".test/androidx.test.runner.AndroidJUnitRunner"], stdout=stream, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 900; sampled = 0
            while True:
                if stopped or time.monotonic() > deadline: raise RuntimeError("upgrade pre-phase stopped or timed out")
                text = prelog.read_text()
                tokens = re.findall(r"APP_SELF_UPGRADE_BIO_READY ([0-9a-f-]+) " + re.escape(run), text)
                pending = [token for token in tokens if "APP_SELF_UPGRADE_BIO_DONE " + token + " " + run not in text]
                if pending and time.monotonic() - sampled > 2:
                    owned(); call("emu", "finger", "touch", "1", stdout=subprocess.DEVNULL); sampled = time.monotonic()
                if "APP_SELF_UPGRADE_APPROVING " + run in text and version() == 2: break
                if process.poll() is not None:
                    if "APP_SELF_UPGRADE_APPROVING " + run not in text or version() != 2:
                        print(text[-12000:], flush=True); raise RuntimeError("instrumentation died before independently proven package replacement")
                    break
                time.sleep(.5)
        owned()
        confirmation = device_json("confirmation.json")
        if confirmation["run_id"] != run or confirmation["sha256"] != receipt["candidate"]["sha256"]:
            raise RuntimeError("confirmation did not bind the full executable target")
        installed = output("shell", "pm", "path", package).strip().removeprefix("package:")
        if not re.fullmatch(r"/data/app/[A-Za-z0-9_./=+~-]+/base\.apk", installed): raise RuntimeError("unexpected installed base APK path")
        actual = output("shell", "sha256sum", installed).split()[0]
        if actual != receipt["candidate"]["sha256"]: raise RuntimeError("installed APK bytes differ from target")
        if process.poll() is None:
            process.wait(timeout=30)
        postlog = source.parent / "post-upgrade.log"
        with postlog.open("w") as stream:
            completed = subprocess.run(adb + ["shell", "am", "instrument", "-w", "-e", "appSelfUpgrade", "true", "-e", "appSelfUpgradeRun", run,
                "-e", "class", package + ".AppSelfUpgradeTest#reopenAfterRealSystemUpgradeAndVerifyIdentityKeysAndRoom", package + ".test/androidx.test.runner.AndroidJUnitRunner"], stdout=stream, stderr=subprocess.STDOUT, timeout=600)
        text = postlog.read_text()
        if completed.returncode != 0 or "OK (1 test)" not in text or "FAILURES" in text:
            print(text[-12000:], flush=True); raise RuntimeError("post-upgrade identity/data acceptance failed")
        verified = device_json("result.json")
        if verified["run_id"] != run or verified["state"] != "passed" or verified["installed_sha256"] != actual:
            raise RuntimeError("native result does not prove this upgrade")
        result.write_text(json.dumps(verified) + "\n"); result.chmod(0o600)
        print("System settings roundtrip, full executable v2 replacement, same identity/keys and encrypted Room recovery passed", flush=True)
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
            call("shell", "am", "force-stop", package, stdout=subprocess.DEVNULL)
        if mode is not None:
            owned(); call("shell", "appops", "set", package, "REQUEST_INSTALL_PACKAGES", mode, stdout=subprocess.DEVNULL)
        if reversed_port:
            call("reverse", "--remove", "tcp:" + str(origin.port), stdout=subprocess.DEVNULL)
        # Result/diagnostic input stay protected in app-private storage on failure.
        if result.exists(): call("shell", "run-as", package, "rm", "-rf", directory, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
