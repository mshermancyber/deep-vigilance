#!/usr/bin/env bash
#
# dv-scan.sh - Deep Vigilance CLI Security Scanner
#
# Launches a security scan via the Deep Vigilance API, polls for completion,
# evaluates findings against a severity threshold, and optionally outputs SARIF.
#
# Usage:
#   dv-scan.sh --api-url https://dv.example.com \
#              --email user@example.com --password secret \
#              --project-id UUID --scan-type sast \
#              --repo-url https://github.com/org/repo.git
#
# Exit codes:
#   0 - Scan passed (no findings above threshold)
#   1 - Scan failed (findings above threshold) or error
#

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────

API_URL=""
EMAIL=""
PASSWORD=""
PROJECT_ID=""
SCAN_TYPE="full"
FAIL_ON="high"
TIMEOUT=600
REPO_URL=""
BRANCH=""
FORMAT="table"   # table | sarif | json

# ── Color / formatting helpers ────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()   { err "$@"; exit 1; }

# ── Usage ─────────────────────────────────────────────────────────────────────

usage() {
  cat <<'USAGE'
dv-scan.sh - Deep Vigilance CLI Scanner

USAGE:
  dv-scan.sh [OPTIONS]

REQUIRED:
  --api-url URL        Base URL of the Deep Vigilance API
  --email EMAIL        API authentication email
  --password PASS      API authentication password
  --project-id UUID    Project UUID in Deep Vigilance

OPTIONS:
  --scan-type TYPE     Scan type: sast|dast|api|sca|full (default: full)
  --fail-on SEVERITY   Fail threshold: critical|high|medium|low|none (default: high)
  --timeout SECONDS    Max wait time for scan (default: 600)
  --repo-url URL       Repository URL for SAST/SCA scans
  --branch BRANCH      Git branch to scan
  --format FORMAT      Output format: table|sarif|json (default: table)
  -h, --help           Show this help

ENVIRONMENT VARIABLES:
  DV_API_URL, DV_EMAIL, DV_PASSWORD, DV_PROJECT_ID
  These can be used instead of (or as defaults for) the corresponding flags.

EXAMPLES:
  # Basic SAST scan
  dv-scan.sh --api-url https://dv.example.com \
    --email ci@company.com --password "$SECRET" \
    --project-id abc-123 --scan-type sast \
    --repo-url https://github.com/org/repo.git

  # Full scan with SARIF output, fail only on critical
  dv-scan.sh --api-url https://dv.example.com \
    --email ci@company.com --password "$SECRET" \
    --project-id abc-123 --fail-on critical --format sarif
USAGE
  exit 0
}

# ── Parse arguments ───────────────────────────────────────────────────────────

# Seed from environment
API_URL="${DV_API_URL:-$API_URL}"
EMAIL="${DV_EMAIL:-$EMAIL}"
PASSWORD="${DV_PASSWORD:-$PASSWORD}"
PROJECT_ID="${DV_PROJECT_ID:-$PROJECT_ID}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-url)     API_URL="$2";     shift 2 ;;
    --email)       EMAIL="$2";       shift 2 ;;
    --password)    PASSWORD="$2";    shift 2 ;;
    --project-id)  PROJECT_ID="$2";  shift 2 ;;
    --scan-type)   SCAN_TYPE="$2";   shift 2 ;;
    --fail-on)     FAIL_ON="$2";     shift 2 ;;
    --timeout)     TIMEOUT="$2";     shift 2 ;;
    --repo-url)    REPO_URL="$2";    shift 2 ;;
    --branch)      BRANCH="$2";      shift 2 ;;
    --format)      FORMAT="$2";      shift 2 ;;
    -h|--help)     usage ;;
    *)             die "Unknown option: $1" ;;
  esac
done

# ── Validate ──────────────────────────────────────────────────────────────────

for cmd in curl jq; do
  command -v "$cmd" &>/dev/null || die "Required command '$cmd' not found. Please install it."
done

[[ -n "$API_URL" ]]    || die "--api-url is required"
[[ -n "$EMAIL" ]]      || die "--email is required"
[[ -n "$PASSWORD" ]]   || die "--password is required"
[[ -n "$PROJECT_ID" ]] || die "--project-id is required"

case "$SCAN_TYPE" in
  sast|dast|api|sca|full) ;;
  *) die "Invalid --scan-type '${SCAN_TYPE}'. Must be: sast, dast, api, sca, full" ;;
esac

case "$FAIL_ON" in
  critical|high|medium|low|none) ;;
  *) die "Invalid --fail-on '${FAIL_ON}'. Must be: critical, high, medium, low, none" ;;
esac

case "$FORMAT" in
  table|sarif|json) ;;
  *) die "Invalid --format '${FORMAT}'. Must be: table, sarif, json" ;;
esac

# Strip trailing slash from API URL
API_URL="${API_URL%/}"

# ── Cookie jar ────────────────────────────────────────────────────────────────

COOKIE_JAR=$(mktemp)
trap 'rm -f "$COOKIE_JAR"' EXIT

# ── Helper: HTTP request ─────────────────────────────────────────────────────

api_get() {
  curl -s -b "$COOKIE_JAR" "$@"
}

api_post() {
  local url="$1"; shift
  curl -s -w "\n%{http_code}" \
    -X POST "$url" \
    -H "Content-Type: application/json" \
    -b "$COOKIE_JAR" \
    "$@"
}

# ── Step 1: Login ─────────────────────────────────────────────────────────────

info "Authenticating with Deep Vigilance..."

LOGIN_RESPONSE=$(curl -s -w "\n%{http_code}" \
  -X POST "${API_URL}/api/auth/login" \
  -H "Content-Type: application/json" \
  -c "$COOKIE_JAR" \
  -d "$(jq -n --arg e "$EMAIL" --arg p "$PASSWORD" '{email:$e, password:$p}')")

LOGIN_HTTP=$(echo "$LOGIN_RESPONSE" | tail -1)
if [[ "$LOGIN_HTTP" != "200" ]]; then
  die "Login failed (HTTP ${LOGIN_HTTP})"
fi

if ! grep -q "access_token" "$COOKIE_JAR"; then
  die "Login returned 200 but no access_token cookie found"
fi

ok "Authenticated."

# ── Step 2: Launch scan ──────────────────────────────────────────────────────

info "Launching ${SCAN_TYPE} scan..."

LAUNCH_OPTIONS=$(jq -n \
  --arg repo "$REPO_URL" \
  --arg branch "$BRANCH" \
  '{repoUrl: $repo, branch: $branch} | with_entries(select(.value != ""))')

LAUNCH_PAYLOAD=$(jq -n \
  --arg pid "$PROJECT_ID" \
  --arg st "$SCAN_TYPE" \
  --arg name "CLI Scan - $(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson opts "$LAUNCH_OPTIONS" \
  '{projectId: $pid, scanType: $st, name: $name, options: $opts}')

LAUNCH_RESPONSE=$(api_post "${API_URL}/api/scans/launch" -d "$LAUNCH_PAYLOAD")
LAUNCH_HTTP=$(echo "$LAUNCH_RESPONSE" | tail -1)
LAUNCH_BODY=$(echo "$LAUNCH_RESPONSE" | sed '$d')

if [[ "$LAUNCH_HTTP" != "200" ]] && [[ "$LAUNCH_HTTP" != "201" ]]; then
  die "Scan launch failed (HTTP ${LAUNCH_HTTP}): ${LAUNCH_BODY}"
fi

SCAN_ID=$(echo "$LAUNCH_BODY" | jq -r '.id // .scanId // .data.id // empty')
if [[ -z "$SCAN_ID" ]]; then
  die "Could not extract scan ID from response: ${LAUNCH_BODY}"
fi

ok "Scan launched: ${SCAN_ID}"

# ── Step 3: Poll for completion ───────────────────────────────────────────────

info "Waiting for scan to complete (timeout: ${TIMEOUT}s)..."

ELAPSED=0
INTERVAL=10
STATUS=""

while [[ "$ELAPSED" -lt "$TIMEOUT" ]]; do
  POLL_RESPONSE=$(api_get "${API_URL}/api/scans/${SCAN_ID}")
  STATUS=$(echo "$POLL_RESPONSE" | jq -r '.status // .data.status // empty')

  case "$STATUS" in
    completed)
      ok "Scan completed."
      break
      ;;
    failed)
      die "Scan failed on the server side"
      ;;
    cancelled)
      die "Scan was cancelled"
      ;;
  esac

  printf "  Status: %-12s  (%ds / %ds)\r" "$STATUS" "$ELAPSED" "$TIMEOUT"
  sleep "$INTERVAL"
  ELAPSED=$((ELAPSED + INTERVAL))
done

if [[ "$STATUS" != "completed" ]]; then
  die "Scan timed out after ${TIMEOUT}s (last status: ${STATUS})"
fi

# ── Step 4: Fetch findings ────────────────────────────────────────────────────

info "Fetching findings..."

FINDINGS_RESPONSE=$(api_get "${API_URL}/api/findings?scanId=${SCAN_ID}&limit=200")
FINDINGS=$(echo "$FINDINGS_RESPONSE" | jq '.data // []')

CRITICAL=$(echo "$FINDINGS" | jq '[.[] | select(.severity == "critical")] | length')
HIGH=$(echo "$FINDINGS"     | jq '[.[] | select(.severity == "high")] | length')
MEDIUM=$(echo "$FINDINGS"   | jq '[.[] | select(.severity == "medium")] | length')
LOW=$(echo "$FINDINGS"      | jq '[.[] | select(.severity == "low")] | length')
INFO_COUNT=$(echo "$FINDINGS" | jq '[.[] | select(.severity == "info")] | length')
TOTAL=$(echo "$FINDINGS"    | jq 'length')

# ── Step 5: Output results ───────────────────────────────────────────────────

if [[ "$FORMAT" == "json" ]]; then
  echo "$FINDINGS" | jq .
elif [[ "$FORMAT" == "sarif" ]]; then
  # Convert findings to SARIF 2.1.0
  echo "$FINDINGS" | jq '{
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
      "tool": {
        "driver": {
          "name": "Deep Vigilance",
          "version": "1.0.0",
          "informationUri": "https://deep-vigilance.dev",
          "rules": [.[] | {
            "id": (.rule_id // .cwe_id // .id),
            "name": (.rule_name // .title),
            "shortDescription": { "text": .title },
            "fullDescription": { "text": (.description // .title) },
            "helpUri": (if .cwe_id then "https://cwe.mitre.org/data/definitions/\(.cwe_id | ltrimstr("CWE-")).html" else null end),
            "properties": {
              "severity": .severity,
              "confidence": (.confidence // "medium")
            }
          }] | unique_by(.id)
        }
      },
      "results": [.[] | {
        "ruleId": (.rule_id // .cwe_id // .id),
        "level": (
          if .severity == "critical" or .severity == "high" then "error"
          elif .severity == "medium" then "warning"
          else "note"
          end
        ),
        "message": { "text": (.description // .title) },
        "locations": [
          if .file_path then {
            "physicalLocation": {
              "artifactLocation": { "uri": .file_path },
              "region": {
                "startLine": (.line_number // 1)
              }
            }
          } else null end
        ] | map(select(. != null))
      }]
    }]
  }'
else
  # Table output
  echo ""
  echo -e "${BOLD}===== Deep Vigilance Scan Results =====${NC}"
  echo -e "  Scan ID:  ${SCAN_ID}"
  echo -e "  Type:     ${SCAN_TYPE}"
  echo ""
  printf "  %-12s %s\n" "Severity" "Count"
  printf "  %-12s %s\n" "--------" "-----"
  printf "  ${RED}%-12s${NC} %s\n" "Critical" "$CRITICAL"
  printf "  ${YELLOW}%-12s${NC} %s\n" "High" "$HIGH"
  printf "  ${CYAN}%-12s${NC} %s\n" "Medium" "$MEDIUM"
  printf "  %-12s %s\n" "Low" "$LOW"
  printf "  %-12s %s\n" "Info" "$INFO_COUNT"
  printf "  %-12s %s\n" "--------" "-----"
  printf "  ${BOLD}%-12s${NC} %s\n" "Total" "$TOTAL"
  echo -e "${BOLD}========================================${NC}"

  # Print top findings if any
  if [[ "$TOTAL" -gt 0 ]]; then
    echo ""
    echo -e "${BOLD}Top Findings:${NC}"
    echo "$FINDINGS" | jq -r '
      sort_by(
        if .severity == "critical" then 0
        elif .severity == "high" then 1
        elif .severity == "medium" then 2
        elif .severity == "low" then 3
        else 4 end
      ) | .[0:10] | .[] |
      "  [\(.severity | ascii_upcase)] \(.title)" +
      (if .file_path then " (\(.file_path)" + (if .line_number then ":\(.line_number)" else "" end) + ")" else "" end)
    '
  fi
fi

# ── Step 6: Evaluate threshold ────────────────────────────────────────────────

SHOULD_FAIL=0
case "$FAIL_ON" in
  critical) [[ "$CRITICAL" -gt 0 ]] && SHOULD_FAIL=1 ;;
  high)     [[ "$CRITICAL" -gt 0 ]] || [[ "$HIGH" -gt 0 ]] && SHOULD_FAIL=1 ;;
  medium)   [[ "$CRITICAL" -gt 0 ]] || [[ "$HIGH" -gt 0 ]] || [[ "$MEDIUM" -gt 0 ]] && SHOULD_FAIL=1 ;;
  low)      [[ "$CRITICAL" -gt 0 ]] || [[ "$HIGH" -gt 0 ]] || [[ "$MEDIUM" -gt 0 ]] || [[ "$LOW" -gt 0 ]] && SHOULD_FAIL=1 ;;
  none)     SHOULD_FAIL=0 ;;
esac

echo ""
if [[ "$SHOULD_FAIL" -eq 1 ]]; then
  err "Security gate FAILED - findings at or above '${FAIL_ON}' severity detected"
  exit 1
else
  ok "Security gate PASSED (threshold: ${FAIL_ON})"
  exit 0
fi
