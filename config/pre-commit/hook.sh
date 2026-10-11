#!/usr/bin/env bash
# =============================================================================
# AppSec Platform — Pre-commit Hook
# M14d: Developer Experience — Pre-commit Security Scanning
# =============================================================================
# Installed via: cp hook.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
# Or via symlink: ln -sf ../../config/pre-commit/hook.sh .git/hooks/pre-commit
# =============================================================================
set -o pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
readonly HOOK_NAME="AppSec Pre-commit"
readonly HOOK_VERSION="1.0.0"
readonly CACHE_DIR=".appsec-cache"
readonly HASH_CACHE_FILE="${CACHE_DIR}/precommit-hashes.txt"
readonly CONFIG_FILE=".appsec-precommit.yml"
readonly STAGED_HASHES_FILE="${CACHE_DIR}/staged-hashes.txt"
readonly LOG_FILE="${CACHE_DIR}/precommit.log"

# Source file extensions we care about
readonly SOURCE_EXTENSIONS='\.(js|ts|py|java|go|rb|php|rs|swift|kt|cs)$'

# Files/directories to always skip
readonly ALWAYS_SKIP_DIRS='(^|/)test/|(^|/)spec/|(^|/)__tests__/|(^|/)vendor/|(^|/)generated/|(^|/)node_modules/|(^|/)\.git/'
readonly ALWAYS_SKIP_EXTS='\.(md|txt|json|lock|log|svg|png|jpg|jpeg|gif|ico|woff|woff2|eot|ttf|otf|pdf|zip|tar|gz|bz2|7z|rar|exe|dll|so|dylib|class|jar|war)$'

# ANSI color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No Color

# Symbols
readonly ICON_PASS="[PASS]"
readonly ICON_WARN="[WARN]"
readonly ICON_BLOCK="[BLOCK]"
readonly ICON_INFO="[INFO]"
readonly ICON_SKIP="[SKIP]"

# ---------------------------------------------------------------------------
# Default configuration (overridden by .appsec-precommit.yml in repo root)
# ---------------------------------------------------------------------------
CONFIG_FAIL_ON_SECRETS="true"
CONFIG_FAIL_ON_SEVERITY="critical"
CONFIG_WARN_ON_SEVERITY="high"
CONFIG_EXCLUDE_PATTERNS="test/|spec/|__tests__/|vendor/|generated/"
CONFIG_MAX_FILE_SIZE_KB=500
CONFIG_TIMEOUT_SECONDS=30
CONFIG_STRICT_MODE="true"

# ---------------------------------------------------------------------------
# Secret and vulnerability regex patterns
# These are adapted from the SAST engine rule library (scanners/src/sast/engine.ts)
# ---------------------------------------------------------------------------
SECRET_PATTERNS=(
  # Hardcoded passwords and credentials
  '(password\s*[:=]\s*["'"'"'][^"'"'"']{4,}["'"'"'])'
  '(secret\s*[:=]\s*["'"'"'][^"'"'"']{8,}["'"'"'])'
  '(api[_-]?key\s*[:=]\s*["'"'"'][A-Za-z0-9_\-\.]{16,}["'"'"'])'
  '(token\s*[:=]\s*["'"'"'][A-Za-z0-9_\-\.]{16,}["'"'"'])'

  # Private keys
  '(-----BEGIN\s+(RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY-----)'

  # AWS keys
  '(AKIA[0-9A-Z]{16})'
  '("?AWS_ACCESS_KEY_ID"?\s*[:=]\s*["'"'"'][A-Za-z0-9/+=]{16,}["'"'"'])'
  '("?AWS_SECRET_ACCESS_KEY"?\s*[:=]\s*["'"'"'][A-Za-z0-9/+=]{40}["'"'"'])'

  # GitHub tokens
  '(ghp_[A-Za-z0-9]{36})'
  '(gho_[A-Za-z0-9]{36})'
  '(ghu_[A-Za-z0-9]{36})'
  '(ghs_[A-Za-z0-9]{36})'

  # GitLab tokens
  '(glpat-[A-Za-z0-9\-_]{20,})'

  # Slack tokens
  '(xox[baprs]-[A-Za-z0-9\-]{10,})'

  # Generic Bearer tokens
  '(Bearer\s+[A-Za-z0-9_\-\.]{20,})'

  # JWT tokens (hardcoded)
  '(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})'

  # Connection strings with credentials
  '(mongodb(?:\+srv)?://[A-Za-z0-9_\-]+:[A-Za-z0-9_\-]+@)'
  '(postgresql://[A-Za-z0-9_\-]+:[A-Za-z0-9_\-]+@)'
  '(mysql://[A-Za-z0-9_\-]+:[A-Za-z0-9_\-]+@)'
  '(redis://:[A-Za-z0-9_\-]+@)'

  # .env or configuration with inline credentials
  '(DATABASE_URL\s*=\s*[A-Za-z0-9_\-]+://[A-Za-z0-9_\-]+:[A-Za-z0-9_\-]+@)'
  '(REDIS_URL\s*=\s*[A-Za-z0-9_\-]+://:[A-Za-z0-9_\-]+@)'

  # Heroku API keys
  '(heroku_api_key\s*[:=]\s*["'"'"'][A-Za-z0-9\-]{36}["'"'"'])'

  # Slack webhook URLs
  '(https://hooks\.slack\.com/services/[A-Za-z0-9/]{40,})'
)

# Critical/high severity vulnerability patterns (adapted from SAST rules)
CRITICAL_PATTERNS=(
  # SQL injection via string concatenation
  '(execute\s*\(\s*["'"'"'].*[\+\$].*["'"'"']\s*\))'
  '(query\s*\(\s*["'"'"'].*[\+\$].*["'"'"']\s*\))'
  '(rawQuery\s*\(\s*["'"'"'].*[\+\$])'
  '(whereRaw\s*\(\s*["'"'"'].*[\+\$])'
  '(findBySql\s*\(\s*["'"'"'].*[\+\$])'
  '(DB::(select|statement|unprepared)\s*\(\s*\$.*\))'
  '(db\.execute\s*\(\s*[a-zA-Z].*\+.*\))'
  '(connection\.query\s*\(\s*[a-zA-Z].*\+.*\))'
  '(cursor\.execute\s*\(\s*[a-zA-Z].*\+.*\))'

  # Command injection
  '(exec\s*\(\s*[^"'"'"'].*)'
  '(execSync\s*\(\s*[^"'"'"'].*)'
  '(shell_exec\s*\(\s*[^"'"'"'].*)'
  '(system\s*\(\s*[^"'"'"'].*)'
  '(child_process\.exec\s*\(\s*[a-zA-Z].*)'
  '(Runtime\.getRuntime\(\)\.exec\s*\()'
  '(os\.system\s*\(\s*[a-zA-Z].*)'
  '(subprocess\.(call|Popen|run)\s*\(\s*[^\[].*)'

  # Insecure deserialization
  '(eval\s*\(\s*[^0-9].*)'
  '(parse\s*\(\s*[^0-9].*)'
  '(JSON\.parse\s*\(\s*[a-zA-Z].*)'
  '(pickle\.loads?\s*\()'
  '(ObjectInputStream\s*\()'
  '(BinaryFormatter\.Deserialize\s*\()'
  '(YAML\.load\s*\(\s*[^s])'
  '(marshal\.loads?\s*\()'

  # XSS sinks (dangerous innerHTML, dangerouslySetInnerHTML)
  '(dangerouslySetInnerHTML\s*=)'
  '(innerHTML\s*=.*[\+\$].*)'
  '(v-html\s*=.*[\+\$].*)'

  # Path traversal
  '(readFile\s*\(\s*.*\+\s*.*\))'
  '(readFileSync\s*\(\s*.*\+\s*.*\))'
  '(open\s*\(\s*.*\+\s*.*\))'
  '(file_get_contents\s*\(\s*\$.*\))'

  # Prototype pollution
  '(\[['"'"']__proto__['"'"']\])'
  '(\[['"'"']constructor['"'"']\]\s*\[['"'"']prototype['"'"']\])'

  # Hardcoded cryptographic keys
  '(aes.?key\s*[:=]\s*["'"'"'][A-Za-z0-9/+=]{16,}["'"'"'])'
  '(private.?key\s*[:=]\s*["'"'"'][A-Za-z0-9/+=]{10,}["'"'"'])'
)

HIGH_PATTERNS=(
  # Debug endpoints left enabled
  '(app\.listen\s*\()'
  '(server\.listen\s*\()'
  '(Debug\.WriteLine)'
  '(console\.log\s*\(\s*["'"'"'].*password)'
  '(logger\.debug\s*\(\s*.*password)'

  # Weak crypto
  '(MD5\s*\(.*\))'
  '(SHA1\s*\(.*\))'
  '(sha1\s*\(.*\))'
  '(md5\s*\(.*\))'
  '(DES\s*\()'
  '(RC4\s*\()'
  '(Cipher\.getInstance\s*\(\s*["'"'"'](DES|RC4|MD5)["'"'"'])'

  # Insecure JWT
  '(jwt\.sign\s*\(\s*\{[^,]*,\s*["'"'"']none["'"'"'])'
  '(algorithm:\s*["'"'"']none["'"'"'])'

  # Unsafe file upload
  '(multer\s*\(\s*\{[^}]*dest[^}]*\})'
  '(file_uploads\s*=\s*[Oo]n)'

  # Cross-site scripting via raw output
  '(\{!!\s*\$.*!!\})'
  '(mark_safe\s*\()'
  '(bypassSecurityTrustHtml\s*\()'
  '(bypassSecurityTrustScript\s*\()'

  # Open redirect
  '(redirect\s*\(\s*\$.*\))'
  '(res\.redirect\s*\(\s*req\.)'
  '(redirect\s*\(\s*request\.)'

  # SSRF
  '(fetch\s*\(\s*[a-zA-Z].*url)'
  '(axios\.(get|post)\s*\(\s*[a-zA-Z].*)'
  '(requests\.(get|post)\s*\(\s*[a-zA-Z].*)'
  '(RestTemplate\.(getForObject|postForObject)\s*\(\s*[a-zA-Z].*)'
  '(http\.Get\s*\(\s*[a-zA-Z].*)'
  '(c\.Get\s*\(\s*["'"'"']/[^"'"'"']*["'"'"']\s*,\s*func)'

  # Missing security headers
  '(app\.use\s*\(\s*cors\s*\(\s*\{[^}]*origin:\s*["'"'"']\*["'"'"'])'
  '(Access-Control-Allow-Origin:\s*\*)'

  # Insecure cookie
  '(httpOnly:\s*false)'
  '(secure:\s*false)'

  # Dangerous eval/Function
  '(Function\s*\(["'"'"'][^"'"'"']*["'"'"']\s*\))'
  '(setTimeout\s*\(\s*["'"'"'][a-zA-Z].*["'"'"'])'
  '(setInterval\s*\(\s*["'"'"'][a-zA-Z].*["'"'"'])'
)

# ---------------------------------------------------------------------------
# Helper: color-coded output
# ---------------------------------------------------------------------------
info()  { echo -e "${CYAN}${ICON_INFO}${NC}  ${1}"; }
pass()  { echo -e "${GREEN}${ICON_PASS}${NC}  ${1}"; }
warn()  { echo -e "${YELLOW}${ICON_WARN}${NC}  ${1}"; }
block() { echo -e "${RED}${ICON_BLOCK}${NC}  ${1}"; }
skip()  { echo -e "${CYAN}${ICON_SKIP}${NC}  ${1}"; }

# ---------------------------------------------------------------------------
# Helper: log to file
# ---------------------------------------------------------------------------
log_message() {
  local level="$1"
  local message="$2"
  local timestamp
  timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
  echo "[${timestamp}] [${level}] ${message}" >> "${LOG_FILE}" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Helper: parse simple YAML config
# Supports:
#   key: value
#   key: "quoted value"
#   listKey:
#     - item1
#     - item2
#   nestedKey:
#     subKey: value
# ---------------------------------------------------------------------------
parse_config() {
  local config_path="$1"
  [[ ! -f "${config_path}" ]] && return 0

  local key value

  while IFS=':' read -r key value; do
    # Trim whitespace
    key="${key##*[[:space:]]}"
    key="${key%%[[:space:]]*}"
    value="${value##*[[:space:]]}"
    value="${value%%[[:space:]]*}"

    # Remove surrounding quotes
    value="${value#\"}"
    value="${value%\"}"
    value="${value#\'}"
    value="${value%\'}"

    case "${key}" in
      failOnSecrets)
        [[ "${value,,}" == "true" || "${value,,}" == "yes" ]] && CONFIG_FAIL_ON_SECRETS="true" || CONFIG_FAIL_ON_SECRETS="${value}"
        ;;
      failOnSeverity)
        CONFIG_FAIL_ON_SEVERITY="${value,,}"
        ;;
      warnOnSeverity)
        CONFIG_WARN_ON_SEVERITY="${value,,}"
        ;;
      excludePatterns)
        CONFIG_EXCLUDE_PATTERNS="${value}"
        ;;
      maxFileSizeKB)
        CONFIG_MAX_FILE_SIZE_KB="${value}"
        ;;
      timeoutSeconds)
        CONFIG_TIMEOUT_SECONDS="${value}"
        ;;
      strictMode)
        [[ "${value,,}" == "true" || "${value,,}" == "yes" ]] && CONFIG_STRICT_MODE="true" || CONFIG_STRICT_MODE="false"
        ;;
    esac
  done < <(grep -E '^[a-zA-Z]' "${config_path}" | grep ':' | head -20)
}

# ---------------------------------------------------------------------------
# Helper: get repo root (handles submodule and bare repos)
# ---------------------------------------------------------------------------
get_repo_root() {
  git rev-parse --show-toplevel 2>/dev/null || echo "."
}

# ---------------------------------------------------------------------------
# Helper: ensure cache directory exists
# ---------------------------------------------------------------------------
ensure_cache_dir() {
  local repo_root
  repo_root="$(get_repo_root)"
  mkdir -p "${repo_root}/${CACHE_DIR}" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Helper: compute SHA-256 hash of file content
# ---------------------------------------------------------------------------
file_hash() {
  local file="$1"
  if command -v sha256sum &>/dev/null; then
    sha256sum "${file}" 2>/dev/null | cut -d' ' -f1
  elif command -v shasum &>/dev/null; then
    shasum -a 256 "${file}" 2>/dev/null | cut -d' ' -f1
  elif command -v openssl &>/dev/null; then
    openssl dgst -sha256 "${file}" 2>/dev/null | cut -d' ' -f2
  else
    # Fallback: use stat mtime + size (less reliable but works without sha256sum)
    stat -c '%Y %s' "${file}" 2>/dev/null
  fi
}

# ---------------------------------------------------------------------------
# Helper: load previously cached hashes
# ---------------------------------------------------------------------------
load_hash_cache() {
  local repo_root
  repo_root="$(get_repo_root)"
  local cache_path="${repo_root}/${HASH_CACHE_FILE}"

  if [[ -f "${cache_path}" ]]; then
    cat "${cache_path}" 2>/dev/null || true
  fi
}

# ---------------------------------------------------------------------------
# Helper: save updated hash cache
# ---------------------------------------------------------------------------
save_hash_cache() {
  local repo_root
  repo_root="$(get_repo_root)"
  local cache_path="${repo_root}/${HASH_CACHE_FILE}"
  mkdir -p "$(dirname "${cache_path}")" 2>/dev/null

  # Write all entries from stdin
  cat > "${cache_path}.tmp" 2>/dev/null
  mv -f "${cache_path}.tmp" "${cache_path}" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Helper: check if file hash has changed since last scan
# Returns 0 (unchanged), 1 (new/changed), or 2 (error)
# ---------------------------------------------------------------------------
hash_changed() {
  local file="$1"
  local current_hash
  current_hash="$(file_hash "${file}")" || return 2
  [[ -z "${current_hash}" ]] && return 2

  local repo_root
  repo_root="$(get_repo_root)"
  local cache_path="${repo_root}/${HASH_CACHE_FILE}"

  if [[ -f "${cache_path}" ]]; then
    local rel_path
    rel_path="${file#"${repo_root}/"}"
    # Check if we have a cached hash for this file
    if grep -q "^${rel_path}|" "${cache_path}" 2>/dev/null; then
      local cached_hash
      cached_hash="$(grep "^${rel_path}|" "${cache_path}" 2>/dev/null | tail -1 | cut -d'|' -f2)"
      if [[ "${cached_hash}" == "${current_hash}" ]]; then
        return 0  # Unchanged
      fi
    fi
  fi

  # Store current hash for later cache update
  echo "${rel_path:-${file}}|${current_hash}" >> "${STAGED_HASHES_FILE}" 2>/dev/null || true
  return 1  # New or changed
}

# ---------------------------------------------------------------------------
# Helper: check if a file should be skipped based on path
# ---------------------------------------------------------------------------
should_skip_file() {
  local file="$1"

  # Skip files matching always-skip extensions
  if echo "${file}" | grep -qE "${ALWAYS_SKIP_EXTS}"; then
    return 0
  fi

  # Skip files matching always-skip directories
  if echo "${file}" | grep -qE "${ALWAYS_SKIP_DIRS}"; then
    return 0
  fi

  # Skip files matching configured exclude patterns
  if echo "${file}" | grep -qE "(${CONFIG_EXCLUDE_PATTERNS})"; then
    return 0
  fi

  return 1
}

# ---------------------------------------------------------------------------
# Helper: check file size limit
# ---------------------------------------------------------------------------
file_exceeds_size_limit() {
  local file="$1"
  local size_kb
  size_kb=$(wc -c < "${file}" 2>/dev/null | awk '{print int($1/1024)}') || return 1
  [[ "${size_kb}" -gt "${CONFIG_MAX_FILE_SIZE_KB}" ]] && return 0 || return 1
}

# ---------------------------------------------------------------------------
# Helper: scan a single file for secrets and vulnerabilities
# Writes results to a temp file passed as the second argument.
# The temp file contains shell-assignable variables.
# ---------------------------------------------------------------------------
scan_file_content() {
  local file_path="$1"
  local result_file="$2"
  local content
  content="$(cat "${file_path}" 2>/dev/null)" || return 1

  local line_num=0
  local secrets_found=0
  local critical_found=0
  local high_found=0
  local secret_lines=""
  local critical_lines=""
  local high_lines=""

  while IFS= read -r line; do
    line_num=$((line_num + 1))

    # Check secrets
    for pattern in "${SECRET_PATTERNS[@]}"; do
      if echo "${line}" | grep -qE "${pattern}"; then
        local masked
        masked="$(echo "${line}" | sed -E 's/([A-Za-z0-9/_\-\.\+:]{8,})[A-Za-z0-9/_\-\.\+:]{4,}/\1****/g')"
        secrets_found=$((secrets_found + 1))
        secret_lines="${secret_lines}__SECRET_LINE__${file_path}:${line_num} — ${masked}
"
        break
      fi
    done

    # Check critical severity patterns
    for pattern in "${CRITICAL_PATTERNS[@]}"; do
      if echo "${line}" | grep -qE "${pattern}"; then
        critical_found=$((critical_found + 1))
        local snippet
        snippet="$(echo "${line}" | sed 's/^[[:space:]]*//' | head -c 120)"
        critical_lines="${critical_lines}__CRITICAL_LINE__${file_path}:${line_num} — ${snippet}
"
        break
      fi
    done

    # Check high severity patterns
    for pattern in "${HIGH_PATTERNS[@]}"; do
      if echo "${line}" | grep -qE "${pattern}"; then
        high_found=$((high_found + 1))
        local snippet2
        snippet2="$(echo "${line}" | sed 's/^[[:space:]]*//' | head -c 120)"
        high_lines="${high_lines}__HIGH_LINE__${file_path}:${line_num} — ${snippet2}
"
        break
      fi
    done

  done <<< "${content}"

  # Write results to temp file as shell-assignable variables
  {
    echo "SECRETS_FOUND=${secrets_found}"
    echo "CRITICAL_FOUND=${critical_found}"
    echo "HIGH_FOUND=${high_found}"
    echo "SECRET_LINES_BEGIN"
    echo -n "${secret_lines}"
    echo "SECRET_LINES_END"
    echo "CRITICAL_LINES_BEGIN"
    echo -n "${critical_lines}"
    echo "CRITICAL_LINES_END"
    echo "HIGH_LINES_BEGIN"
    echo -n "${high_lines}"
    echo "HIGH_LINES_END"
  } > "${result_file}"
}

# ---------------------------------------------------------------------------
# Main scan logic
# ---------------------------------------------------------------------------
main() {
  local repo_root
  repo_root="$(get_repo_root)"

  # ------------------------------------------------------------------
  # Header
  # ------------------------------------------------------------------
  echo ""
  echo -e "${BOLD}${HOOK_NAME} v${HOOK_VERSION}${NC}"
  echo -e "${CYAN}────────────────────────────────────────────────────${NC}"
  echo ""

  # ------------------------------------------------------------------
  # Load config from repo root if present
  # ------------------------------------------------------------------
  local config_path="${repo_root}/${CONFIG_FILE}"
  if [[ -f "${config_path}" ]]; then
    parse_config "${config_path}"
    info "Loaded configuration from ${CONFIG_FILE}"
  else
    info "No ${CONFIG_FILE} found — using defaults"
  fi
  echo ""

  # ------------------------------------------------------------------
  # Ensure cache directory exists
  # ------------------------------------------------------------------
  ensure_cache_dir

  # ------------------------------------------------------------------
  # Remove stale staged-hashes file
  # ------------------------------------------------------------------
  rm -f "${STAGED_HASHES_FILE}" 2>/dev/null || true

  # ------------------------------------------------------------------
  # Get list of staged files
  # ------------------------------------------------------------------
  local staged_files
  staged_files="$(git diff --cached --name-only --diff-filter=ACMRT 2>/dev/null)" || {
    warn "Unable to get staged files. Is this a git repository?"
    echo ""
    echo -e "${GREEN}${HOOK_NAME}: Allowing commit (cannot determine staged files).${NC}"
    exit 0
  }

  # Remove empty lines
  staged_files="$(echo "${staged_files}" | grep -v '^$' || true)"

  if [[ -z "${staged_files}" ]]; then
    info "No staged files to scan."
    echo ""
    echo -e "${GREEN}${HOOK_NAME}: Allowing commit.${NC}"
    exit 0
  fi

  # ------------------------------------------------------------------
  # Filter to source files and process
  # ------------------------------------------------------------------
  local source_files=()
  local skipped_files=()
  local binary_files=()

  while IFS= read -r file; do
    [[ -z "${file}" ]] && continue

    # Check extension
    if ! echo "${file}" | grep -qE "${SOURCE_EXTENSIONS}"; then
      # Silently skip non-source files — too noisy otherwise
      continue
    fi

    local full_path="${repo_root}/${file}"

    # Check if file exists on disk (could have been deleted)
    if [[ ! -f "${full_path}" ]]; then
      continue
    fi

    # Check if file should be skipped
    if should_skip_file "${file}"; then
      skipped_files+=("${file}")
      continue
    fi

    source_files+=("${file}")
  done <<< "${staged_files}"

  # Report skipped files
  if [[ ${#skipped_files[@]} -gt 0 ]]; then
    skip "Skipped ${#skipped_files[@]} file(s) matching exclude patterns"
    for sf in "${skipped_files[@]}"; do
      echo -e "       ${sf}"
    done
    echo ""
  fi

  if [[ ${#source_files[@]} -eq 0 ]]; then
    pass "No source files to scan (all staged files are excluded or non-source)."
    echo ""
    echo -e "${GREEN}${HOOK_NAME}: Allowing commit.${NC}"
    exit 0
  fi

  info "Scanning ${#source_files[@]} staged source file(s)..."
  echo ""

  # ------------------------------------------------------------------
  # Scan each file
  # ------------------------------------------------------------------
  local total_secrets=0
  local total_critical=0
  local total_high=0
  local total_skipped=0
  local scanned_count=0
  local cache_hit_count=0
  local result_output=""

  for file in "${source_files[@]}"; do
    local full_path="${repo_root}/${file}"

    # Check file size
    if file_exceeds_size_limit "${full_path}"; then
      echo -e "  ${YELLOW}[SKIP]${NC} ${file} (exceeds ${CONFIG_MAX_FILE_SIZE_KB}KB limit)"
      total_skipped=$((total_skipped + 1))
      continue
    fi

    # Check hash cache
    local file_hash_val
    file_hash_val="$(file_hash "${full_path}")"
    local cached_match=false

    hash_changed "${full_path}"
    local hash_status=$?

    if [[ ${hash_status} -eq 0 ]]; then
      # File unchanged — skip scan
      echo -e "  ${CYAN}[CACHED]${NC} ${file} (hash unchanged — using previous results)"
      cache_hit_count=$((cache_hit_count + 1))
      continue
    fi

    # Scan the file
    scanned_count=$((scanned_count + 1))
    echo -e "  ${BOLD}[SCAN]${NC} ${file}"

    # Run scan — write results to a temp file
    local scan_result_file
    scan_result_file="$(mktemp /tmp/appsec-precommit-XXXXXX)" 2>/dev/null || scan_result_file="${repo_root}/${CACHE_DIR}/scan-result-$$.tmp"
    scan_file_content "${full_path}" "${scan_result_file}" || true

    # Parse results from the temp file
    local file_secrets=0
    local file_critical=0
    local file_high=0
    local file_secret_lines=""
    local file_critical_lines=""
    local file_high_lines=""

    local in_section=""
    while IFS= read -r result_line; do
      case "${result_line}" in
        SECRETS_FOUND=*)
          file_secrets="${result_line#*=}"
          ;;
        CRITICAL_FOUND=*)
          file_critical="${result_line#*=}"
          ;;
        HIGH_FOUND=*)
          file_high="${result_line#*=}"
          ;;
        SECRET_LINES_BEGIN)
          in_section="SECRET"
          ;;
        SECRET_LINES_END)
          in_section=""
          ;;
        CRITICAL_LINES_BEGIN)
          in_section="CRITICAL"
          ;;
        CRITICAL_LINES_END)
          in_section=""
          ;;
        HIGH_LINES_BEGIN)
          in_section="HIGH"
          ;;
        HIGH_LINES_END)
          in_section=""
          ;;
        __SECRET_LINE__*)
          local line_content="${result_line#__SECRET_LINE__}"
          file_secret_lines="${file_secret_lines}${line_content}"$'\n'
          ;;
        __CRITICAL_LINE__*)
          local line_content="${result_line#__CRITICAL_LINE__}"
          file_critical_lines="${file_critical_lines}${line_content}"$'\n'
          ;;
        __HIGH_LINE__*)
          local line_content="${result_line#__HIGH_LINE__}"
          file_high_lines="${file_high_lines}${line_content}"$'\n'
          ;;
      esac
    done < "${scan_result_file}"
    rm -f "${scan_result_file}" 2>/dev/null || true

    # Accumulate totals
    total_secrets=$((total_secrets + file_secrets))
    total_critical=$((total_critical + file_critical))
    total_high=$((total_high + file_high))

    # Output findings for this file
    if [[ -n "${file_secret_lines}" ]]; then
      while IFS= read -r sl; do
        [[ -z "${sl}" ]] && continue
        block "${sl}"
      done <<< "${file_secret_lines}"
    fi
    if [[ -n "${file_critical_lines}" ]]; then
      while IFS= read -r cl; do
        [[ -z "${cl}" ]] && continue
        block "${cl}"
      done <<< "${file_critical_lines}"
    fi
    if [[ -n "${file_high_lines}" ]]; then
      while IFS= read -r hl; do
        [[ -z "${hl}" ]] && continue
        warn "${hl}"
      done <<< "${file_high_lines}"
    fi

    if [[ ${file_secrets} -eq 0 && ${file_critical} -eq 0 && ${file_high} -eq 0 ]]; then
      pass "  ${file} — clean"
    fi
  done

  echo ""

  # ------------------------------------------------------------------
  # Update hash cache with newly scanned files
  # ------------------------------------------------------------------
  if [[ -f "${STAGED_HASHES_FILE}" ]]; then
    local repo_root2
    repo_root2="$(get_repo_root)"
    local cache_path="${repo_root2}/${HASH_CACHE_FILE}"

    # Merge with existing cache: keep old entries, add/update new ones
    if [[ -f "${cache_path}" ]]; then
      # Remove old entries for files we just scanned, then append new ones
      while IFS='|' read -r cached_file cached_hash; do
        [[ -z "${cached_file}" ]] && continue
        if grep -q "^${cached_file}|" "${STAGED_HASHES_FILE}" 2>/dev/null; then
          continue  # Skip — we have a newer hash
        fi
        echo "${cached_file}|${cached_hash}"
      done < "${cache_path}" > "${cache_path}.merged" 2>/dev/null || true

      cat "${STAGED_HASHES_FILE}" >> "${cache_path}.merged" 2>/dev/null || true
      mv -f "${cache_path}.merged" "${cache_path}" 2>/dev/null || true
    else
      # First time — just use staged hashes
      cp "${STAGED_HASHES_FILE}" "${cache_path}" 2>/dev/null || true
    fi
    rm -f "${STAGED_HASHES_FILE}" 2>/dev/null || true
  fi

  # ------------------------------------------------------------------
  # Summary
  # ------------------------------------------------------------------
  echo -e "${BOLD}Scan Summary:${NC}"
  echo -e "  ${BOLD}${#source_files[@]}${NC} total source files"
  echo -e "  ${GREEN}${cache_hit_count}${NC} cache hits (skipped)"
  echo -e "  ${CYAN}${scanned_count}${NC} files scanned"
  [[ ${total_skipped} -gt 0 ]] && echo -e "  ${YELLOW}${total_skipped}${NC} files skipped (size limit)"
  echo ""
  echo -e "  Secrets found:    ${RED}${total_secrets}${NC}"
  echo -e "  Critical findings: ${RED}${total_critical}${NC}"
  echo -e "  High findings:     ${YELLOW}${total_high}${NC}"
  echo ""

  # ------------------------------------------------------------------
  # Decision logic
  # ------------------------------------------------------------------
  local should_block=false
  local should_warn=false
  local block_reasons=()

  # Secrets block the commit
  if [[ "${CONFIG_FAIL_ON_SECRETS}" == "true" && "${total_secrets}" -gt 0 ]]; then
    should_block=true
    block_reasons+=("${total_secrets} hardcoded secret(s) found")
  fi

  # Critical findings block the commit
  if [[ "${CONFIG_FAIL_ON_SEVERITY}" == "critical" && "${total_critical}" -gt 0 ]]; then
    should_block=true
    block_reasons+=("${total_critical} critical severity finding(s) found")
  fi

  # High findings warn but don't block (unless strict mode is enabled and failOnSeverity allows it)
  if [[ "${total_high}" -gt 0 ]]; then
    if [[ "${CONFIG_STRICT_MODE}" == "true" && "${CONFIG_WARN_ON_SEVERITY}" == "high" ]]; then
      should_warn=true
    fi
  fi

  # If configured, also fail on high
  if [[ "${CONFIG_FAIL_ON_SEVERITY}" == "high" && "${total_high}" -gt 0 ]]; then
    should_block=true
    block_reasons+=("${total_high} high severity finding(s) found")
  fi

  # ------------------------------------------------------------------
  # Output result
  # ------------------------------------------------------------------
  if [[ "${should_block}" == "true" ]]; then
    echo -e "${RED}${BOLD}✗ COMMIT BLOCKED${NC}"
    echo ""
    echo "Reason(s):"
    for reason in "${block_reasons[@]}"; do
      echo -e "  ${RED}· ${reason}${NC}"
    done
    echo ""
    echo -e "${YELLOW}To bypass: ${NC}git commit --no-verify (logged for audit)"
    echo -e "${YELLOW}To fix:    ${NC}Remove hardcoded secrets / fix critical findings and re-stage"
    echo ""
    log_message "ERROR" "Commit blocked: ${block_reasons[*]} (${#source_files[@]} files scanned)"
    exit 1

  elif [[ "${should_warn}" == "true" ]]; then
    echo -e "${YELLOW}${BOLD}⚠  WARNINGS FOUND${NC}"
    echo ""
    echo -e "${total_high} high severity finding(s) detected."
    echo -e "${YELLOW}These do not block the commit but should be reviewed.${NC}"
    echo ""
    # Prompt user
    echo -n -e "${BOLD}Commit anyway? [y/N]${NC} "
    read -r user_input < /dev/tty || true
    echo ""

    case "${user_input}" in
      y|Y|yes|YES)
        echo -e "${GREEN}${HOOK_NAME}: Commit allowed with warnings (user acknowledged).${NC}"
        log_message "WARN" "Commit allowed with warnings: ${total_high} high findings (user acknowledged)"
        exit 0
        ;;
      *)
        echo -e "${RED}${HOOK_NAME}: Commit cancelled by user.${NC}"
        echo ""
        echo -e "${YELLOW}To bypass: ${NC}git commit --no-verify"
        log_message "INFO" "Commit cancelled by user due to ${total_high} high findings"
        exit 1
        ;;
    esac

  else
    echo -e "${GREEN}${BOLD}✓ COMMIT ALLOWED${NC}"
    echo ""
    pass "No blocking issues found."
    echo ""
    log_message "INFO" "Commit allowed: clean scan (${#source_files[@]} files)"
    exit 0
  fi
}

# ---------------------------------------------------------------------------
# Run the hook (capture all output and ensure clean exit)
# ---------------------------------------------------------------------------
main "$@"
