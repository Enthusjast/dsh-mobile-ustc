#!/usr/bin/env python3
"""Run Go/PostgreSQL tests and real npm DSH in a disposable socket-only cluster."""

import os
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile
import re
import json
import sys


def main():
    arguments = argparse.ArgumentParser()
    arguments.add_argument("--kotlin-relay", action="store_true", help="Also run the actual Kotlin Relay client against Go/PostgreSQL over TLS")
    arguments.add_argument("--android-relay", metavar="SERIAL", help="Run the APK/Go/DSH composition on an explicitly owned emulator")
    arguments.add_argument("--android-upgrade", metavar="SERIAL", help="Run actual full APK self-upgrade with host OIDC/API surviving replacement")
    arguments.add_argument("--upgrade-receipt", type=Path, help="Verified full-executable version-2 fixture receipt")
    arguments.add_argument("--android-avd", default="dsh-remote-api26", help="Exact owned AVD identity for the Android composition")
    arguments.add_argument("--go-run", metavar="REGEX", help="Run matching Go cases in the isolated cluster, without the separate Node composition")
    arguments.add_argument("--cross-node", action="store_true", help="Run the real npm DSH composition with Host and phone entering separate mutually authenticated relay processes")
    arguments.add_argument("--dsh-only", action="store_true", help="Run the DSH composition without repeating the separate Go test suite")
    arguments.add_argument("--host-renewal", action="store_true", help="Wait for a real five-minute Host credential renewal in the standalone native DSH composition")
    arguments.add_argument("--installation-revoke", action="store_true", help="Use the registered owner-phone API to retire the normal DSH installation at the end of the standalone composition")
    arguments.add_argument("--host-account-retire", action="store_true", help="Cancel the fixture account source and verify Host plugin retirement without native DSH shutdown")
    arguments.add_argument("--database-outage", action="store_true", help="Exercise a bounded isolated-database outage and recovery in its own two-node DSH composition")
    arguments.add_argument("--relay-crash", action="store_true", help="Kill only the owned Host relay child and reconcile native DSH after natural node-lease expiry and explicit restart")
    arguments.add_argument("--relay-certificate-renewal", action="store_true", help="Renew only isolated relay leaf certificates and keys, restart each owned node, and reconcile native DSH")
    arguments.add_argument("--relay-load", type=int, metavar="CONNECTIONS", help="Opt-in authenticated TLS capacity probe with an equal Host/phone split")
    arguments.add_argument("--load-output", type=Path, help="Fresh evidence directory strictly inside repository .local")
    arguments.add_argument("--load-workers", type=int)
    arguments.add_argument("--load-hold-seconds", type=int)
    arguments.add_argument("--load-active-pairs", type=int)
    arguments.add_argument("--load-events-per-second", type=int)
    arguments.add_argument("--load-payload-bytes", type=int)
    arguments.add_argument("--load-race", action="store_true", help="Race-instrument both service and probe; use only for protocol smoke, not capacity measurements")
    arguments.add_argument("--host-bundle-directory", type=Path, help="Use a protected, offline-verified Host npm bundle in the native composition")
    arguments.add_argument("--host-bundle-manifest-sha256", help="Independently trusted manifest digest for the explicit Host bundle")
    options = arguments.parse_args()
    if (options.host_bundle_directory is None) != (options.host_bundle_manifest_sha256 is None):
        arguments.error("Host bundle directory and manifest digest must be supplied together")
    if options.host_bundle_directory is not None and (not options.dsh_only or not options.host_bundle_directory.is_absolute() or not re.fullmatch(r"[0-9a-f]{64}", options.host_bundle_manifest_sha256)):
        arguments.error("Host bundle requires --dsh-only, an absolute directory and a pinned manifest digest")
    if options.cross_node and (options.go_run or options.relay_load or options.android_relay or options.android_upgrade or options.kotlin_relay):
        arguments.error("--cross-node requires its own native DSH composition invocation")
    if options.dsh_only and (options.go_run or options.relay_load is not None or options.android_relay or options.android_upgrade or options.kotlin_relay):
        arguments.error("--dsh-only selects the native DSH composition, optionally with --cross-node")
    if options.host_renewal and not options.dsh_only:
        arguments.error("--host-renewal requires --dsh-only, optionally with --cross-node")
    if options.relay_certificate_renewal and (not options.dsh_only or not options.cross_node or options.host_renewal or options.installation_revoke or options.host_account_retire or options.database_outage or options.relay_crash):
        arguments.error("--relay-certificate-renewal requires its own --cross-node --dsh-only composition")
    if options.relay_crash and (not options.dsh_only or not options.cross_node or options.host_renewal or options.installation_revoke or options.host_account_retire or options.database_outage):
        arguments.error("--relay-crash requires its own --cross-node --dsh-only composition")
    if options.database_outage and (not options.dsh_only or not options.cross_node or options.host_renewal or options.installation_revoke or options.host_account_retire):
        arguments.error("--database-outage requires its own --cross-node --dsh-only composition")
    if options.host_account_retire and (not options.dsh_only or options.host_renewal or options.installation_revoke):
        arguments.error("--host-account-retire requires its own --dsh-only composition, optionally with --cross-node")
    if options.installation_revoke and (not options.dsh_only or options.host_renewal):
        arguments.error("--installation-revoke requires its own --dsh-only composition, optionally with --cross-node")
    load_fields = (options.load_output, options.load_workers, options.load_hold_seconds, options.load_active_pairs, options.load_events_per_second, options.load_payload_bytes)
    if options.relay_load is None and (any(value is not None for value in load_fields) or options.load_race):
        arguments.error("load options require --relay-load")
    if options.relay_load is not None:
        if not sys.platform.startswith("linux") or options.android_upgrade or options.android_relay or options.kotlin_relay or options.go_run or not options.load_output:
            arguments.error("--relay-load requires Linux, --load-output and its own invocation")
        load = {"connections": options.relay_load, "race": options.load_race, "workers": options.load_workers if options.load_workers is not None else 32,
                "hold_seconds": options.load_hold_seconds if options.load_hold_seconds is not None else 30,
                "active_pairs": options.load_active_pairs if options.load_active_pairs is not None else 0,
                "events_per_second": options.load_events_per_second if options.load_events_per_second is not None else 20,
                "payload_bytes": options.load_payload_bytes if options.load_payload_bytes is not None else 512}
        if not (4 <= load["connections"] <= 12000 and load["connections"] % 2 == 0 and 1 <= load["workers"] <= 64 and
                5 <= load["hold_seconds"] <= 90 and 0 <= load["active_pairs"] <= min(2000, load["connections"] // 2) and
                1 <= load["events_per_second"] <= 20 and 128 <= load["payload_bytes"] <= 16384):
            arguments.error("load configuration outside supported fixture bounds")
        if not options.load_race and any(flag in {"-race", "-race=true"} for flag in os.environ.get("GOFLAGS", "").split()):
            arguments.error("capacity measurements require ordinary non-race service/probe binaries")
    if options.android_upgrade is not None and (not re.fullmatch(r"emulator-[0-9]+", options.android_upgrade) or not re.fullmatch(r"dsh-remote-api(?:26|36)", options.android_avd)):
        arguments.error("--android-upgrade requires an exact dedicated test AVD")
    if options.android_upgrade and (options.android_relay or options.kotlin_relay or options.go_run or not options.upgrade_receipt):
        arguments.error("--android-upgrade requires --upgrade-receipt and its own composition invocation")
    if options.upgrade_receipt and not options.android_upgrade:
        arguments.error("--upgrade-receipt requires --android-upgrade")
    android_serial = options.android_upgrade or options.android_relay
    if options.android_relay is not None and not options.android_relay:
        arguments.error("An explicit nonempty owned-emulator serial is required")
    if options.android_relay and options.kotlin_relay:
        arguments.error("Select either Kotlin JVM composition or Android APK composition")
    if options.android_relay and options.go_run:
        arguments.error("The Android composition selects its own Go case")
    repo = Path(__file__).resolve().parents[2]
    if options.host_bundle_directory is not None:
        checked = subprocess.run([sys.executable, str(repo / "tools/release/host_bundle.py"), "verify", "--directory", str(options.host_bundle_directory),
                                  "--expected-manifest-sha256", options.host_bundle_manifest_sha256], capture_output=True, timeout=15)
        if checked.returncode != 0:
            arguments.error("Host bundle failed offline verification before opening composition resources")

    if options.relay_load is not None:
        options.load_output = options.load_output.resolve()
        if not options.load_output.is_relative_to((repo / ".local").resolve()) or options.load_output == (repo / ".local").resolve() or options.load_output.exists():
            arguments.error("load output must be a fresh directory strictly inside repository .local")
    kotlin_classpath = None
    java = None
    adb = None
    if android_serial:
        adb = os.environ.get("REMOTE_TEST_ADB") or str(repo / ".local/android-sdk/platform-tools/adb")
        if not Path(adb).is_file():
            adb = shutil.which("adb")
        if not adb:
            raise SystemExit("Set REMOTE_TEST_ADB to the installed Android platform-tools adb.")
        subprocess.run([str(repo / "android/gradlew"), "--no-daemon", "--max-workers=1", "-Pkotlin.compiler.execution.strategy=in-process", ":app:assembleDebug", ":app:assembleDebugAndroidTest"], cwd=repo / "android", check=True)
        name = subprocess.run([adb, "-s", android_serial, "emu", "avd", "name"], check=True, capture_output=True, text=True, timeout=15).stdout.splitlines()[0]
        if name != options.android_avd or not android_serial.startswith("emulator-"):
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
            postgres_options = "-h '' -k " + root + " -p 55439" + (" -c log_error_verbosity=verbose" if options.relay_load is not None else "")
            subprocess.run([str(pg_bin / "pg_ctl"), "-D", str(data), "-l", str(log), "-o", postgres_options, "-w", "start"], check=True, stdout=subprocess.DEVNULL)
            started = True
            dsn = "host=" + root + " port=55439 user=dsh_e2e dbname=postgres sslmode=disable"
            for migration in sorted((repo / "deploy/sql").glob("*.up.sql")):
                subprocess.run([str(pg_bin / "psql"), "-X", "--dbname", dsn, "-v", "ON_ERROR_STOP=1", "-q", "-f", str(migration)], check=True, stdout=subprocess.DEVNULL)
            subprocess.run([go, "build"] + (["-race"] if options.load_race else []) + ["-o", str(binary), "./cmd/remote"], cwd=repo / "services/remote", check=True)
            if not options.android_upgrade and options.relay_load is None:
                subprocess.run(["npm", "run", "build"], cwd=repo, check=True)
            env = dict(os.environ, REMOTE_TEST_CLUSTER_ROOT=root, REMOTE_TEST_DATABASE_URL=dsn,
                       REMOTE_TEST_PSQL=str(pg_bin / "psql"), REMOTE_TEST_PG_DUMP=str(pg_bin / "pg_dump"), REMOTE_TEST_SERVICE_BIN=str(binary))
            # Activation is explicit per invocation, never inherited from a prior run.
            for field in ("REMOTE_TEST_CROSS_NODE", "REMOTE_TEST_HOST_RENEWAL", "REMOTE_TEST_INSTALLATION_REVOKE", "REMOTE_TEST_HOST_ACCOUNT_RETIRE", "REMOTE_TEST_DATABASE_OUTAGE", "REMOTE_TEST_RELAY_CRASH", "REMOTE_TEST_RELAY_CERTIFICATE_RENEWAL", "REMOTE_TEST_HOST_BUNDLE_DIRECTORY", "REMOTE_TEST_HOST_BUNDLE_MANIFEST_SHA256", "REMOTE_TEST_KOTLIN_CLASSPATH", "REMOTE_TEST_ANDROID_SERIAL", "REMOTE_TEST_ANDROID_BIOMETRIC", "REMOTE_TEST_ANDROID_UPGRADE_SERIAL", "REMOTE_TEST_ANDROID_UPGRADE_RECEIPT", "REMOTE_TEST_RELAY_CAPACITY_CONFIG", "REMOTE_TEST_RELAY_CAPACITY_OUTPUT"):
                env.pop(field, None)
            if options.host_bundle_directory is not None:
                env["REMOTE_TEST_HOST_BUNDLE_DIRECTORY"] = str(options.host_bundle_directory)
                env["REMOTE_TEST_HOST_BUNDLE_MANIFEST_SHA256"] = options.host_bundle_manifest_sha256
            if options.cross_node:
                env["REMOTE_TEST_CROSS_NODE"] = "1"
            if options.host_renewal:
                env["REMOTE_TEST_HOST_RENEWAL"] = "1"
            if options.installation_revoke:
                env["REMOTE_TEST_INSTALLATION_REVOKE"] = "1"
            if options.host_account_retire:
                env["REMOTE_TEST_HOST_ACCOUNT_RETIRE"] = "1"
            if options.database_outage:
                env["REMOTE_TEST_DATABASE_OUTAGE"] = "1"
            if options.relay_crash:
                env["REMOTE_TEST_RELAY_CRASH"] = "1"
            if options.relay_certificate_renewal:
                env["REMOTE_TEST_RELAY_CERTIFICATE_RENEWAL"] = "1"
            if options.relay_load is not None:
                env.update(REMOTE_TEST_RELAY_CAPACITY_CONFIG=json.dumps(load), REMOTE_TEST_RELAY_CAPACITY_OUTPUT=str(options.load_output))
                completed = subprocess.run([go, "test"] + (["-race"] if options.load_race else []) + ["-count=1", "-v", "-timeout=9m", "-run", "^TestAuthenticatedRelayCapacity$", "./internal/httpapi"], cwd=repo / "services/remote", env=env)
                states = {}
                for state in re.findall(r"ERROR:\s+([0-9A-Z]{5}):", log.read_text()):
                    states[state] = states.get(state, 0) + 1
                if options.load_output.is_dir():
                    diagnostic = options.load_output / "postgres-sqlstates.json"
                    diagnostic.write_text(json.dumps({"sqlstate_error_counts": states}, indent=2) + "\n")
                    diagnostic.chmod(0o600)
                print("PostgreSQL SQLSTATE counts: " + json.dumps(states, sort_keys=True), flush=True)
                if completed.returncode:
                    return completed.returncode
                result = json.loads((options.load_output / "summary.json").read_text())
                if result["state"] != "passed" or result["config"] != load:
                    raise RuntimeError("capacity probe did not prove this requested workload")
                print("Authenticated capacity evidence: " + str(options.load_output), flush=True)
                return 0
            if options.android_upgrade:
                env.update(REMOTE_TEST_ANDROID_UPGRADE_SERIAL=options.android_upgrade, REMOTE_TEST_ANDROID_AVD=options.android_avd,
                           REMOTE_TEST_ADB=adb, REMOTE_TEST_ANDROID_UPGRADE_RECEIPT=str(options.upgrade_receipt.resolve()))
                return subprocess.run([go, "test", "-race", "-count=1", "-v", "-timeout=30m", "-run", "^TestAndroidAppSelfUpgradePreservesIdentityAndData$", "./internal/httpapi"],
                                      cwd=repo / "services/remote", env=env).returncode
            if options.android_relay:
                env.update(REMOTE_TEST_ANDROID_SERIAL=options.android_relay, REMOTE_TEST_ANDROID_AVD=options.android_avd,
                           REMOTE_TEST_ADB=adb, REMOTE_TEST_ANDROID_BIOMETRIC="1")
                # Keep the full race suite separate from the software emulator.
                # This one composition necessarily runs its Go server beside the APK.
                return subprocess.run([go, "test", "-race", "-count=1", "-v", "-timeout=12m", "-run", "^TestAndroidAppAgainstPostgresRelayAndNativeDSH$", "./internal/httpapi"],
                                      cwd=repo / "services/remote", env=env).returncode
            if kotlin_classpath:
                env.update(REMOTE_TEST_KOTLIN_CLASSPATH=kotlin_classpath, REMOTE_TEST_JAVA=java)
            if not options.dsh_only:
                # Each Go integration test owns a private database in this cluster.
                # Running here ensures the security tests cannot silently skip PG.
                command = [go, "test", "-race", "-count=1"]
                if options.go_run:
                    command += ["-run", options.go_run, "-v"]
                result = subprocess.run(command + ["./..."], cwd=repo / "services/remote", env=env)
                if result.returncode:
                    return result.returncode
                if options.go_run:
                    return 0
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
