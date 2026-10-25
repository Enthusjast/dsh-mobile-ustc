#!/usr/bin/env python3
"""Run Go/PostgreSQL tests and real npm DSH in a disposable socket-only cluster."""

import os
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    arguments = argparse.ArgumentParser()
    arguments.add_argument("--kotlin-relay", action="store_true", help="Also run the actual Kotlin Relay client against Go/PostgreSQL over TLS")
    arguments.add_argument("--android-relay", metavar="SERIAL", help="Run the APK/Go/DSH composition on an explicitly owned emulator")
    arguments.add_argument("--android-avd", default="dsh-remote-api26", help="Exact owned AVD identity for the Android composition")
    options = arguments.parse_args()
    if options.android_relay is not None and not options.android_relay:
        arguments.error("An explicit nonempty owned-emulator serial is required")
    if options.android_relay and options.kotlin_relay:
        arguments.error("Select either Kotlin JVM composition or Android APK composition")
    repo = Path(__file__).resolve().parents[2]
    kotlin_classpath = None
    java = None
    adb = None
    if options.android_relay:
        adb = os.environ.get("REMOTE_TEST_ADB") or str(repo / ".local/android-sdk/platform-tools/adb")
        if not Path(adb).is_file():
            adb = shutil.which("adb")
        if not adb:
            raise SystemExit("Set REMOTE_TEST_ADB to the installed Android platform-tools adb.")
        subprocess.run([str(repo / "android/gradlew"), "--no-daemon", "--max-workers=1", "-Pkotlin.compiler.execution.strategy=in-process", ":app:assembleDebug", ":app:assembleDebugAndroidTest"], cwd=repo / "android", check=True)
        name = subprocess.run([adb, "-s", options.android_relay, "emu", "avd", "name"], check=True, capture_output=True, text=True, timeout=15).stdout.splitlines()[0]
        if name != options.android_avd or not options.android_relay.startswith("emulator-"):
            raise SystemExit("The Android composition requires the exact dedicated owned AVD.")
    if options.kotlin_relay:
        java = shutil.which("java")
        if not java:
            raise SystemExit("Install JDK 17 or 21 to run the Kotlin Relay probe.")
        subprocess.run([str(repo / "android/gradlew"), "-PjvmOnly=true", ":core:network:writeFixtureClasspath"], cwd=repo / "android", check=True)
        kotlin_classpath = (repo / "android/core/network/build/fixtures/classpath.txt").read_text().strip()
    pg_bin = Path(os.environ.get("REMOTE_TEST_PG_BIN", "/usr/lib/postgresql/18/bin"))
    go = os.environ.get("REMOTE_TEST_GO") or shutil.which("go")
    if not go and Path("/opt/go1.26.10/bin/go").is_file():
        go = "/opt/go1.26.10/bin/go"
    if not go or not all((pg_bin / name).is_file() for name in ("initdb", "pg_ctl", "psql", "pg_dump")):
        raise SystemExit("Set REMOTE_TEST_GO and REMOTE_TEST_PG_BIN to installed Go and PostgreSQL binaries.")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise SystemExit("Run as an unprivileged user; PostgreSQL initdb refuses root.")
    with tempfile.TemporaryDirectory(prefix="dsh-go-e2e-") as root:
        fixture_root = Path(root)
        data, log = fixture_root / "pgdata", fixture_root / "postgres.log"
        binary = fixture_root / "remote"
        started = False
        try:
            subprocess.run([str(pg_bin / "initdb"), "-D", str(data), "--auth=trust", "--username=dsh_e2e", "--no-locale", "--encoding=UTF8"], check=True, stdout=subprocess.DEVNULL)
            subprocess.run([str(pg_bin / "pg_ctl"), "-D", str(data), "-l", str(log), "-o", "-h '' -k " + root + " -p 55439", "-w", "start"], check=True, stdout=subprocess.DEVNULL)
            started = True
            dsn = "host=" + root + " port=55439 user=dsh_e2e dbname=postgres sslmode=disable"
            for migration in sorted((repo / "deploy/sql").glob("*.up.sql")):
                subprocess.run([str(pg_bin / "psql"), "-X", "--dbname", dsn, "-v", "ON_ERROR_STOP=1", "-q", "-f", str(migration)], check=True, stdout=subprocess.DEVNULL)
            subprocess.run([go, "build", "-o", str(binary), "./cmd/remote"], cwd=repo / "services/remote", check=True)
            subprocess.run(["npm", "run", "build"], cwd=repo, check=True)
            env = dict(os.environ, REMOTE_TEST_CLUSTER_ROOT=root, REMOTE_TEST_DATABASE_URL=dsn,
                       REMOTE_TEST_PSQL=str(pg_bin / "psql"), REMOTE_TEST_PG_DUMP=str(pg_bin / "pg_dump"), REMOTE_TEST_SERVICE_BIN=str(binary))
            # Activation is explicit per invocation, never inherited from a prior run.
            for field in ("REMOTE_TEST_KOTLIN_CLASSPATH", "REMOTE_TEST_ANDROID_SERIAL", "REMOTE_TEST_ANDROID_BIOMETRIC"):
                env.pop(field, None)
            if options.android_relay:
                env.update(REMOTE_TEST_ANDROID_SERIAL=options.android_relay, REMOTE_TEST_ANDROID_AVD=options.android_avd,
                           REMOTE_TEST_ADB=adb, REMOTE_TEST_ANDROID_BIOMETRIC="1")
                # Keep the full race suite separate from the software emulator.
                # This one composition necessarily runs its Go server beside the APK.
                return subprocess.run([go, "test", "-race", "-count=1", "-v", "-timeout=12m", "-run", "^TestAndroidAppAgainstPostgresRelayAndNativeDSH$", "./internal/httpapi"],
                                      cwd=repo / "services/remote", env=env).returncode
            if kotlin_classpath:
                env.update(REMOTE_TEST_KOTLIN_CLASSPATH=kotlin_classpath, REMOTE_TEST_JAVA=java)
            # Each Go integration test owns a private database in this cluster.
            # Running here ensures the security tests cannot silently skip PG.
            result = subprocess.run([go, "test", "-race", "-count=1", "./..."], cwd=repo / "services/remote", env=env)
            if result.returncode:
                return result.returncode
            result = subprocess.run([str(repo / "node_modules/.bin/tsx"), "--test", str(repo / "tools/integration/remote-dsh.test.ts")], cwd=repo, env=env)
            if result.returncode:
                for line in log.read_text().splitlines():
                    if "ERROR:" in line:
                        print(line, flush=True)
            return result.returncode
        finally:
            if started:
                subprocess.run([str(pg_bin / "pg_ctl"), "-D", str(data), "-m", "immediate", "-w", "stop"], check=True, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    raise SystemExit(main())
