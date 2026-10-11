#!/bin/bash
# Smoke Test — validates entire platform after docker compose up --build
set -e

BASE="${BASE:-https://localhost:8443/api}"
PASS=0
FAIL=0

check() {
  local desc="$1" method="$2" url="$3" expected="$4" data="${5:-}"
  local code
  if [ -z "$data" ]; then
    code=$(curl -sk -o /dev/null -w "%{http_code}" -X "$method" "$url")
  else
    code=$(curl -sk -o /dev/null -w "%{http_code}" -X "$method" "$url" -H "Content-Type: application/json" -d "$data")
  fi
  if [ "$code" = "$expected" ]; then
    echo "  ✅ $desc (HTTP $code)"
    PASS=$((PASS+1))
  else
    echo "  ❌ $desc (expected $expected, got $code)"
    FAIL=$((FAIL+1))
  fi
}

echo "🔍 AppSec Platform Smoke Test"
echo "=============================="
echo ""

echo "1. Health Checks"
check "Liveness" GET "$BASE/health/liveness" 200
check "Readiness" GET "$BASE/health/readiness" 200
check "Full health" GET "$BASE/health" 200
echo ""

echo "2. Authentication"
check "Login with valid creds" POST "$BASE/auth/login" 200 '{"email":"admin@example.com","password":"Admin123!@#ChangeMe"}'
check "Login with bad password" POST "$BASE/auth/login" 401 '{"email":"admin@example.com","password":"wrong"}'
check "Register validation" POST "$BASE/auth/register" 400 '{"email":"bad","password":"short"}'
echo ""

# Get token
TOKEN=$(curl -sk -X POST "$BASE/auth/login" -H "Content-Type: application/json" -d '{"email":"admin@example.com","password":"Admin123!@#ChangeMe"}' | grep -o '"accessToken":"[^"]*"' | cut -d'"' -f4)
AUTH="Authorization: Bearer $TOKEN"

echo "3. Authenticated Endpoints"
check "Get dashboard" GET "$BASE/dashboard/summary" 200
check "List projects" GET "$BASE/projects?limit=5" 200
check "List scans" GET "$BASE/scans?limit=5" 200
check "List findings" GET "$BASE/findings?limit=5" 200
check "Get current user" GET "$BASE/auth/me" 200
check "List reports" GET "$BASE/reports?limit=5" 200
check "List schedules" GET "$BASE/scheduler?limit=5" 200
check "List users" GET "$BASE/users?limit=5" 200
check "List audit log" GET "$BASE/admin/audit-log?limit=5" 200
check "System health" GET "$BASE/admin/system-health" 200
check "Global search" GET "$BASE/search?q=test" 200
echo ""

echo "4. RBAC Enforcement"
check "Unauthenticated access" GET "$BASE/projects" 401
check "Missing token" GET "$BASE/findings" 401
echo ""

echo "5. API Version"
VERSION=$(curl -sk "$BASE/version" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
echo "  Platform version: $VERSION"
echo ""

echo "=============================="
echo "Results: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then exit 1; fi
echo "✅ All smoke tests passed!"
