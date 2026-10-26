#!/usr/bin/env python3
"""Owned-emulator transport for the explicit APK/Go/DSH composition. No phone private keys leave Android."""
import json
import os
import pathlib
import re
import shlex
import signal
import subprocess
import sys
import time
import uuid
from urllib.parse import urlparse


def main():
    repo = pathlib.Path(__file__).resolve().parents[2]
    cluster = pathlib.Path(os.environ["REMOTE_TEST_CLUSTER_ROOT"]).resolve()
    source, serial, result = pathlib.Path(sys.argv[1]).resolve(), sys.argv[2], pathlib.Path(sys.argv[3]).resolve()
    if not source.is_relative_to(cluster) or not result.is_relative_to(cluster) or source.stat().st_mode & 0o077:
        raise RuntimeError("protected private-cluster fixture required")
    fixture = json.loads(source.read_text())
    run_id = str(uuid.UUID(fixture["run_id"]))
    if run_id != fixture["run_id"] or not re.fullmatch(r"emulator-[0-9]+", serial):
        raise RuntimeError("explicit owned emulator required")
    adb = [os.environ["REMOTE_TEST_ADB"], "-s", serial]
    expected_avd = os.environ.get("REMOTE_TEST_ANDROID_AVD", "dsh-remote-api26")

    def call(args, **kwargs):
        return subprocess.run(adb + args, check=True, timeout=kwargs.pop("timeout", 30), **kwargs)

    def owned():
        name = call(["emu", "avd", "name"], capture_output=True, text=True).stdout.splitlines()[0]
        if name != expected_avd:
            raise RuntimeError("owned AVD identity changed")

    owned()
    package = "cn.edu.ustc.dsh.mobile"
    directory = "no_backup/device-composition/" + run_id
    ports = set()
    for origin in (fixture["deployment"]["remote_origin"], fixture["object_origin"]):
        endpoint = urlparse(origin)
        if endpoint.scheme != "https" or endpoint.hostname not in ("127.0.0.1", "localhost", "::1") or endpoint.port is None or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment:
            raise RuntimeError("explicit local TLS fixture endpoint required")
        ports.add(str(endpoint.port))
    reverses = []
    process = None
    log = source.parent / "android-instrumentation.log"
    try:
        print("Android phase: install test APKs", flush=True)
        for apk in (repo / "android/app/build/outputs/apk/debug/app-debug.apk", repo / "android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"):
            call(["install", "-r", str(apk)], timeout=180, stdout=subprocess.DEVNULL)
        existing = call(["reverse", "--list"], capture_output=True, text=True).stdout
        for port in sorted(ports):
            if any("tcp:" + port in line.split() for line in existing.splitlines()):
                raise RuntimeError("fixture reverse port is already in use")
            call(["reverse", "tcp:" + port, "tcp:" + port], stdout=subprocess.DEVNULL)
            reverses.append(port)
        call(["shell", "run-as", package, "mkdir", "-p", directory], stdout=subprocess.DEVNULL)
        script = "umask 077; cat > " + directory + "/input.json"
        call(["shell", "run-as", package, "sh", "-c", shlex.quote(script)], input=source.read_bytes(), stdout=subprocess.DEVNULL)
        print("Android phase: run actual application composition", flush=True)
        with log.open("w") as stream:
            process = subprocess.Popen(adb + ["shell", "am", "instrument", "-w", "-e", "deviceComposition", "true", "-e", "deviceCompositionRun", run_id,
                "-e", "class", "cn.edu.ustc.dsh.mobile.DeviceCompositionTest", package + ".test/androidx.test.runner.AndroidJUnitRunner"], stdout=stream, stderr=subprocess.STDOUT)
            stopped = False

            def stop(*_):
                nonlocal stopped
                stopped = True

            signal.signal(signal.SIGTERM, stop)
            signal.signal(signal.SIGINT, stop)
            deadline, sampled = time.monotonic() + 540, 0
            while process.poll() is None:
                if stopped or time.monotonic() > deadline:
                    raise RuntimeError("native instrumentation cancelled or timed out")
                progress = log.read_text()
                pending = [token for token in re.findall(r"DEVICE_COMPOSITION_BIOMETRIC_READY " + re.escape(run_id) + r" ([0-9a-f-]+)", progress)
                           if "DEVICE_COMPOSITION_BIOMETRIC_DONE " + run_id + " " + token not in progress]
                if pending and os.environ.get("REMOTE_TEST_ANDROID_BIOMETRIC") == "1" and time.monotonic() - sampled > 2:
                    owned()
                    call(["emu", "finger", "touch", "1"], stdout=subprocess.DEVNULL)
                    sampled = time.monotonic()
                time.sleep(0.5)
            text = log.read_text()
            if process.returncode != 0 or "OK (1 test)" not in text or "FAILURES" in text:
                print(text[-6000:], flush=True)
                raise RuntimeError("native composition did not pass")
        encoded = call(["shell", "run-as", package, "cat", directory + "/result.json"], capture_output=True).stdout
        metadata = json.loads(encoded)
        if metadata.get("run_id") != run_id or metadata.get("state") != "passed":
            raise RuntimeError("native result does not match this run")
        result.write_bytes(encoded)
        result.chmod(0o600)
        print("Native APK PKCE/DPoP, device registration, biometric allow/reject, scanned files, verified export saves and encrypted reopen passed", flush=True)
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
            call(["shell", "am", "force-stop", package], stdout=subprocess.DEVNULL)
        for port in reversed(reverses):
            call(["reverse", "--remove", "tcp:" + port], stdout=subprocess.DEVNULL)
        call(["shell", "run-as", package, "rm", "-rf", directory], stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # No fixture input, token, JWS, private key or raw HTTP body is included.
        print("Android device runner failed: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
