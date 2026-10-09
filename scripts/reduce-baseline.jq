# Reduces a doctor/1 `scan --json` envelope to what a baseline comparison needs and nothing else: no ATR, no EF
# contents, no messages, evidence or locations (under full visibility those can name an IMSI or ICCID).
# Used by the GitHub Action to write the baseline it offers for committing, and by `jq -f` for manual baselines:
#   sim-doctor scan --json | jq -f scripts/reduce-baseline.jq > .sim-doctor/baseline.json
{schema, tool, version, findings: [.findings[] | {id, fingerprint, severity}], data: {run: .data.run}}
