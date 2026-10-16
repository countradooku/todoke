#!/usr/bin/env bash
# The app's instrumented tests on the emulator the workflow started
# (android.yml). Each test is bounded (the runner's timeout_msec), and so is
# the whole run: on API 24 the run has sometimes stopped making progress
# right after "Running tests on devices" until the job's limit, with
# nothing to show why. Logcat is kept for the artifact either way; a run
# that times out is tried once more after stopping the app on the device.
# A test that fails fails the job at once.
set -uo pipefail

adb="$ANDROID_HOME/platform-tools/adb"
logs=apps/android/app/build/outputs/ci-logs
mkdir -p "$logs"
"$adb" logcat -c || true

for attempt in 1 2; do
    "$adb" logcat -v threadtime > "$logs/logcat-$attempt.txt" 2>&1 &
    logcat=$!
    timeout --kill-after=1m 15m \
        gradle --no-daemon -p apps/android :app:connectedPlayDebugAndroidTest \
        -Ptodoke.android="$PWD/crates/todoke-ffi/target-tests/android" \
        -Pandroid.testInstrumentationRunnerArguments.timeout_msec=180000
    status=$?
    kill "$logcat" 2>/dev/null
    # 124: timed out; 137: killed after the grace period.
    if [ "$status" -ne 124 ] && [ "$status" -ne 137 ]; then
        exit "$status"
    fi
    echo "::warning::the instrumented tests made no progress for 15 minutes (attempt $attempt); logcat kept"
    "$adb" shell ps > "$logs/ps-$attempt.txt" 2>&1 || true
    "$adb" shell dumpsys activity activities > "$logs/activities-$attempt.txt" 2>&1 || true
    for package in $("$adb" shell pm list packages org.todoke | tr -d '\r' | sed 's/^package://'); do
        "$adb" shell am force-stop "$package" || true
    done
done
echo "::error::the instrumented tests timed out twice"
exit 1
