#!/usr/bin/env bash
# Body of the sim-doctor GitHub Action (action.yml): one `sim-doctor scan`, gated on NEW findings when a baseline file
# is committed, with a markdown summary and a SARIF file.
#
# Local run: SIM_DOCTOR=target/release/sim-doctor BASELINE=.sim-doctor/baseline.json scripts/sim-doctor-action.sh
# Env: SIM_DOCTOR (command, default sim-doctor), BASELINE (default .sim-doctor/baseline.json; a missing file means
#      no gate), SEVERITY, READER, OUT (default ./sim-doctor-out), GITHUB_OUTPUT, GITHUB_STEP_SUMMARY.
# Exit: 0 ok, 1 gate failed (regressed --diff), 2 tool failure (refusal, exit 129/130, unreadable envelope).
set -uo pipefail

read -ra sd <<< "${SIM_DOCTOR:-sim-doctor}"
baseline=${BASELINE:-.sim-doctor/baseline.json}
out=${OUT:-sim-doctor-out}
mkdir -p "$out"
summary="$out/summary.md"
sarif="$out/sim-doctor.sarif"

args=(scan --json --sarif "$sarif")
[ -n "${SEVERITY:-}" ] && args+=(--severity "$SEVERITY")
[ -n "${READER:-}" ] && args+=(--reader "$READER")
gated=0
if [ -f "$baseline" ]; then
  args+=(--baseline "$baseline" --diff)
  gated=1
else
  echo "::notice::no baseline file at the baseline path; scanning and reporting without a gate"
fi

"${sd[@]}" "${args[@]}" > "$out/envelope.json" 2> "$out/stderr.txt"
rc=$?

# Everything shown comes from the card or the tool, so it is untrusted: python parses the envelope (never grep),
# strips control characters, backticks, pipes, @ and `::`, and picks the exit status.
python3 - "$out/envelope.json" "$rc" "$gated" "$summary" << 'PY'
import json, sys

path, rc, gated, summary = sys.argv[1], int(sys.argv[2]), sys.argv[3] == "1", sys.argv[4]


def clean(v, n=300):
    s = "".join(c if c.isprintable() else " " for c in str(v))
    for bad in "`|@":
        s = s.replace(bad, "_")
    return s.replace("::", ": :")[:n].strip()


try:
    data = json.load(open(path))["payload"]["data"]
    if not isinstance(data, dict):
        raise ValueError("no data block")
except Exception:
    data = None

lines = ["<!-- sim-doctor -->", "### sim-doctor", "", "| | |", "|---|---|"]
status, err = 0, None
if data is None:
    status, err = 2, f"no usable envelope on stdout (exit {rc})"
elif rc not in (0, 1):
    status, err = 2, f"sim-doctor exited {rc}"
elif "error" in data:
    e = data["error"]
    status, err = 2, e.get("message", e.get("kind", "error")) if isinstance(e, dict) else e
elif rc == 1 and "diff" not in data:
    status, err = 2, "exit 1 without a diff or an error"
elif rc == 1:
    status = 1

if status == 2:
    lines.append("| Result | TOOL FAILURE |")
    lines.append(f"| Error | {clean(err)} |")
    print(f"::error::sim-doctor tool failure: {clean(err)}")
else:
    lines.append("| Result | " + ("GATE FAILED" if status else "ok") + " |")
    found = (data.get("findings") or {}).get("findings") or []
    counts = {}
    for f in found:
        sev = clean(f.get("severity", "unknown") if isinstance(f, dict) else "unknown", 20)
        counts[sev] = counts.get(sev, 0) + 1
    for sev, n in sorted(counts.items()):
        lines.append(f"| {sev} | {n} |")
    lines.append(f"| Findings | {len(found)} |")
    diff = data.get("diff")
    if isinstance(diff, dict):
        c = diff.get("counts") or {}
        lines.append(f"| New findings | {clean(c.get('new', '?'), 10)} |")
        lines.append(f"| Fixed since baseline | {clean(c.get('fixed', '?'), 10)} |")
    elif not gated:
        lines.append("| Gate | none (no baseline file) |")
    if isinstance(data.get("score"), dict) and "value" in data["score"]:
        lines.append(f"| Score | {clean(data['score']['value'], 10)} |")

open(summary, "w").write("\n".join(lines) + "\n")
sys.exit(status)
PY
status=$?

[ -n "${GITHUB_STEP_SUMMARY:-}" ] && cat "$summary" >> "$GITHUB_STEP_SUMMARY"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "summary=$summary" >> "$GITHUB_OUTPUT"
  [ -f "$sarif" ] && echo "sarif=$sarif" >> "$GITHUB_OUTPUT"
fi
cat "$summary"
exit "$status"
