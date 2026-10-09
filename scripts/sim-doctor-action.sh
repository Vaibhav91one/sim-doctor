#!/usr/bin/env bash
# Body of the sim-doctor GitHub Action (action.yml): one `sim-doctor scan`, gated on NEW findings against a committed
# baseline file, with a markdown summary and a SARIF file.
#
# Local run: SIM_DOCTOR=target/release/sim-doctor BASELINE=.sim-doctor/baseline.json scripts/sim-doctor-action.sh
# The baseline file is a saved doctor/1 envelope: `sim-doctor scan --json > .sim-doctor/baseline.json`.
# Env: SIM_DOCTOR (command, default sim-doctor), BASELINE (default .sim-doctor/baseline.json), REQUIRE_BASELINE
#      (default true: a missing baseline file is a tool failure; false: scan and report without a gate), SEVERITY,
#      FAIL_ON (passed to --fail-on), READER, OUT (default ./sim-doctor-out, emptied at the start), GITHUB_OUTPUT,
#      GITHUB_STEP_SUMMARY.
# Exit: 0 ok, 1 gate failed (the CLI exited 3: a new finding against the baseline), 2 tool failure (CLI exit 2/130,
#       an error envelope, an unreadable or incomplete envelope, missing baseline, bad input).
# The reduced baseline to commit is written to $OUT/baseline.json (jq scripts/reduce-baseline.jq; needs jq).
# Without a baseline the run only reports: a CLI exit 1 (findings at or above --fail-on) is shown as NOT GATED.
set -uo pipefail

read -ra sd <<< "${SIM_DOCTOR:-sim-doctor}"
baseline=${BASELINE:-.sim-doctor/baseline.json}
require=${REQUIRE_BASELINE:-true}
out=${OUT:-sim-doctor-out}
mkdir -p "$out"
# A stale summary or SARIF from an earlier run must never be published.
find "$out" -mindepth 1 -delete
summary="$out/summary.md"
sarif="$out/sim-doctor.sarif"

# What is shown is untrusted: control characters, backticks, pipes, @, brackets and angle brackets are neutralised
# and "::" broken so a workflow command cannot start.
san() { printf '%s' "$1" | tr -c '[:print:]' ' ' | tr '`|@[]<>' '_' | sed 's/::/: :/g' | cut -c1-300; }

publish() {
  [ -n "${GITHUB_STEP_SUMMARY:-}" ] && cat "$summary" >> "$GITHUB_STEP_SUMMARY"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "summary=$summary" >> "$GITHUB_OUTPUT"
    [ -f "$sarif" ] && echo "sarif=$sarif" >> "$GITHUB_OUTPUT"
  fi
  cat "$summary"
}

early() {
  printf '<!-- sim-doctor -->\n### sim-doctor\n\n| | |\n|---|---|\n| Result | TOOL FAILURE |\n| Error | %s |\n' "$1" > "$summary"
  echo "::error::sim-doctor: $1"
  publish
  exit 2
}

case "${READER:-}" in -*) early "the reader name must not start with a dash" ;; esac
case "${FAIL_ON:-}" in ""|info|low|medium|high|critical) ;; *) early "fail-on must be one of info, low, medium, high, critical" ;; esac

args=(scan --json --sarif "$sarif")
[ -n "${SEVERITY:-}" ] && args+=(--severity "$SEVERITY")
[ -n "${READER:-}" ] && args+=(--reader "$READER")
[ -n "${FAIL_ON:-}" ] && args+=(--fail-on "$FAIL_ON")
gated=0
if [ -f "$baseline" ]; then
  args+=(--baseline "$baseline")
  gated=1
elif [ "$require" != false ]; then
  early "baseline file not found: $(san "$baseline") (commit the reduced baseline this action writes, or one made with sim-doctor scan --json | jq -f scripts/reduce-baseline.jq, or set require-baseline to false)"
else
  echo "::warning::no baseline file at $(san "$baseline"); this run reports but cannot fail on new findings"
fi

"${sd[@]}" "${args[@]}" > "$out/envelope.json" 2> "$out/stderr.txt"
rc=$?

# python parses the envelope (never grep) and exits 0 ok, 10 gate failed, 12 tool failure. Any other status,
# including a crash of the parser itself, is mapped to a tool failure below, never to a gate failure.
python3 - "$out/envelope.json" "$rc" "$gated" "$summary" << 'PY'
import json, sys

path, rc, gated, summary = sys.argv[1], int(sys.argv[2]), sys.argv[3] == "1", sys.argv[4]


def clean(v, n=300):
    s = "".join(c if c.isprintable() else " " for c in str(v))
    for bad in "`|@[]<>":
        s = s.replace(bad, "_")
    return s.replace("::", ": :")[:n].strip()


def build():
    try:
        with open(path, encoding="utf-8") as f:
            env = json.load(f)
        if not isinstance(env, dict) or env.get("schema") != "doctor/1" or not isinstance(env.get("data"), dict):
            raise ValueError("not a doctor/1 envelope")
        data = env["data"]
    except Exception:
        env = data = None

    lines = ["<!-- sim-doctor -->", "### sim-doctor", "", "| | |", "|---|---|"]
    status, err = 0, None
    if data is None:
        status, err = 2, f"no usable envelope on stdout (exit {rc})"
    elif "error" in data:
        e = data["error"]
        status, err = 2, e.get("message", e.get("kind", "error")) if isinstance(e, dict) else e
    elif rc not in (0, 1, 3):
        status, err = 2, f"sim-doctor exited {rc}"
    elif env.get("exit_code") != rc:
        status, err = 2, "the envelope exit_code does not match the exit status"
    elif gated and not isinstance(env.get("baseline"), dict):
        status, err = 2, "the CLI did not report a baseline comparison"
    elif gated and rc == 1:
        status, err = 2, "exit 1 is not a baseline result"
    elif not gated and rc == 3:
        status, err = 2, "exit 3 without a baseline"
    elif rc == 3:
        status = 1

    if status == 2:
        lines.append("| Result | TOOL FAILURE |")
        lines.append(f"| Error | {clean(err)} |")
        print(f"::error::sim-doctor tool failure: {clean(err)}")
        return status, lines
    lines.append("| Result | " + ("GATE FAILED" if status else "ok") + " |")
    found = env.get("findings")
    if not isinstance(found, list):
        raise ValueError("findings is not a list")
    counts = {}
    for f in found:
        sev = clean(f.get("severity", "unknown") if isinstance(f, dict) else "unknown", 20)
        counts[sev] = counts.get(sev, 0) + 1
    for sev, n in sorted(counts.items()):
        lines.append(f"| {sev} | {n} |")
    lines.append(f"| Findings | {len(found)} |")
    base = env.get("baseline")
    if isinstance(base, dict):
        lines.append(f"| New findings | {clean(base.get('new', '?'), 10)} |")
        lines.append(f"| Fixed since baseline | {clean(base.get('fixed', '?'), 10)} |")
    else:
        lines.append("| NOT GATED | no baseline file, this run cannot fail on new findings |")
    if isinstance(env.get("score"), dict) and "value" in env["score"]:
        lines.append(f"| Score | {clean(env['score']['value'], 10)} |")
    return status, lines


try:
    status, lines = build()
except Exception as e:  # an envelope of an unexpected shape is a tool failure, never a verdict
    status = 2
    msg = f"could not read the envelope ({type(e).__name__})"
    lines = ["<!-- sim-doctor -->", "### sim-doctor", "", "| | |", "|---|---|",
             "| Result | TOOL FAILURE |", f"| Error | {msg} |"]
    print(f"::error::sim-doctor tool failure: {msg}")
with open(summary, "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")
sys.exit({0: 0, 1: 10, 2: 12}[status])
PY
pystatus=$?
case "$pystatus" in 0) status=0 ;; 10) status=1 ;; *) status=2 ;; esac
if [ ! -s "$summary" ]; then
  printf '<!-- sim-doctor -->\n### sim-doctor\n\n| | |\n|---|---|\n| Result | TOOL FAILURE |\n| Error | the summary could not be written |\n' > "$summary"
  status=2
fi

# The baseline this run offers for committing, in REDUCED form (no ATR, EF contents, messages or evidence: see
# scripts/reduce-baseline.jq). Written only from an envelope of a scan that ran; a refusal has no run record.
baseline_out="$out/baseline.json"
if [ "$status" != 2 ] && command -v jq > /dev/null 2>&1; then
  if jq -f "$(dirname "$0")/reduce-baseline.jq" "$out/envelope.json" > "$baseline_out" 2> /dev/null; then
    [ -n "${GITHUB_OUTPUT:-}" ] && echo "baseline=$baseline_out" >> "$GITHUB_OUTPUT"
  else
    rm -f "$baseline_out"
  fi
elif [ "$status" != 2 ]; then
  echo "::warning::jq is not installed, so no reduced baseline was written; save one with sim-doctor scan --json and reduce it with scripts/reduce-baseline.jq"
fi

publish
exit "$status"
