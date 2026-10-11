# Inline Scan API

The Application Security Platform provides synchronous and asynchronous scanning endpoints for SAST (Static Analysis), secret detection, SCA (Software Composition Analysis), and DAST (Dynamic Analysis).

**Base URL:** `http://localhost:3000`

---

## Authentication

All scan endpoints require authentication. Choose one of the following methods:

| Method                          | Header / Mechanism                        | Notes                                      |
| ------------------------------- | ----------------------------------------- | ------------------------------------------ |
| **JWT Bearer token**            | `Authorization: Bearer <access_token>`    | Access token obtained via `/api/auth/login` |
| **JWT HttpOnly cookie**         | `Cookie: access_token=<token>`            | Set automatically on login (SPA-friendly)  |
| **X-API-Key**                   | `X-API-Key: <api_key>`                    | API keys managed via `/api/api-client`     |

The inline scan endpoint (`POST /api/scan/inline`) works with any authenticated principal (JWT or API key).  
The scan-launch and scan-status endpoints additionally require specific permissions (see each endpoint).

### Rate Limiting

All endpoints are rate-limited to **120 requests per minute** per API key or IP address.  
A `429 Too Many Requests` response is returned when the limit is exceeded.

---

## 1. POST /api/scan/inline — Synchronous Multi-Engine Scan

Performs SAST, secret detection, and optionally SCA (manifest-based dependency vulnerability lookup) in a single synchronous request/response cycle.

### Request

```
POST /api/scan/inline
Content-Type: application/json
```

| Field      | Type   | Required | Description                                                                 |
| ---------- | ------ | -------- | --------------------------------------------------------------------------- |
| `filename` | string | Yes      | File name (including extension) used to detect language and manifest type.  |
| `content`  | string | Yes      | Raw file contents to scan. Max 5 MB.                                       |
| `language` | string | No       | Override auto-detected language. Use when `filename` is ambiguous.          |

### Response

**200 OK**

```json
{
  "findings": [
    {
      "ruleId": "js-eval-injection",
      "ruleName": "Eval Injection",
      "severity": "high",
      "cweId": "CWE-95",
      "line": 1,
      "message": "Use of eval() with user-controlled input allows arbitrary code execution.",
      "snippet": "eval(userInput)",
      "engine": "sast"
    }
  ],
  "durationMs": 47
}
```

#### InlineFinding Shape

| Field      | Type   | Description                                                                    |
| ---------- | ------ | ------------------------------------------------------------------------------ |
| `ruleId`   | string | Unique identifier for the rule (e.g. `js-eval-injection`, pattern ID, CVE ID) |
| `ruleName` | string | Human-readable rule or vulnerability name                                      |
| `severity` | string | One of `critical`, `high`, `medium`, `low`                                    |
| `cweId`    | string | CWE identifier, or empty string if not applicable                              |
| `line`     | number | Line number where the finding was detected (0 = not line-specific)             |
| `message`  | string | Description or recommendation                                                  |
| `snippet`  | string | The code snippet or secret that triggered the finding                          |
| `engine`   | string | Discriminator: `sast`, `secret`, or `sca`                                     |

#### Engine Behaviour

- **SAST (`engine: "sast"`)** — Always runs. Uses the detected/provided language to apply the appropriate rule set.
- **Secrets (`engine: "secret"`)** — Always runs. Detects credentials, API keys, tokens, private keys, certificates, and connection strings. Severity is mapped based on secret type.
- **SCA (`engine: "sca"`)** — Runs only when `filename` matches a recognised manifest name:

  | Filename           | Ecosystem   |
  | ------------------ | ----------- |
  | `package.json`     | npm         |
  | `requirements.txt` | PyPI        |
  | `go.mod`           | Go          |
  | `pom.xml`          | Maven       |
  | `Gemfile`          | RubyGems    |
  | `Cargo.toml`       | Cargo/Rust  |
  | `composer.json`    | Composer/PHP |

  Dependencies are extracted from the manifest content and checked against the vulnerability database. If the lookup fails, SAST and secret results are still returned.

### cURL Examples

#### SAST (JavaScript)

```bash
curl -X POST http://localhost:3000/api/scan/inline \
  -H 'X-API-Key: $API_KEY' \
  -H 'Content-Type: application/json' \
  -d '{"filename":"test.js","content":"eval(userInput)"}'
```

#### Secret Detection

```bash
curl -X POST http://localhost:3000/api/scan/inline \
  -H 'X-API-Key: $API_KEY' \
  -H 'Content-Type: application/json' \
  -d '{
    "filename": "config.sh",
    "content": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nexport AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  }'
```

#### SCA (npm manifest)

```bash
curl -X POST http://localhost:3000/api/scan/inline \
  -H 'X-API-Key: $API_KEY' \
  -H 'Content-Type: application/json' \
  -d '{
    "filename": "package.json",
    "content": "{\"dependencies\":{\"lodash\":\"4.17.15\",\"express\":\"4.17.1\"},\"devDependencies\":{\"mocha\":\"8.0.0\"}}"
  }'
```

#### JWT Bearer variant

```bash
TOKEN=$(curl -s http://localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"changeme"}' | jq -r '.accessToken')

curl -X POST http://localhost:3000/api/scan/inline \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"filename":"app.py","content":"import os; os.system(user_input)"}'
```

---

## 2. POST /api/scans/launch — Async DAST Scan Launch

Launches an asynchronous DAST (dynamic) scan against a target URL. The scan is queued and processed by background workers.

**Required permission:** `SCAN_LAUNCH`

### Request

```
POST /api/scans/launch
Content-Type: application/json
```

| Field                    | Type   | Required | Description                                                        |
| ------------------------ | ------ | -------- | ------------------------------------------------------------------ |
| `projectId`              | uuid   | Yes      | ID of an existing project the scan belongs to.                     |
| `scanType`               | string | Yes      | Must be `"dast"` for DAST scans (also supports `sast`, `api`, `sca`, `full`). |
| `name`                   | string | Yes      | Human-readable scan name (1–200 chars).                            |
| `options.targetUrl`      | string | Yes      | The target URL to scan (must be a valid URL).                      |
| `options.targetPath`     | string | No       | Local filesystem path (for SAST scans).                            |
| `options.repoUrl`        | string | No       | Git repository URL (for SAST from repo).                           |
| `options.branch`         | string | No       | Git branch to scan (default: main).                                |
| `priority`               | string | No       | One of `low`, `normal`, `high`, `critical` (default: `normal`).   |

### Response

**201 Created**

```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": "queued",
  "scanType": "dast"
}
```

### cURL Example

```bash
curl -X POST http://localhost:3000/api/scans/launch \
  -H 'X-API-Key: $API_KEY' \
  -H 'Content-Type: application/json' \
  -d '{
    "projectId": "e8f3a9b1-2c4d-5e6f-7a8b-9c0d1e2f3a4b",
    "scanType": "dast",
    "name": "Production DAST scan",
    "options": {
      "targetUrl": "https://staging.example.com"
    },
    "priority": "high"
  }'
```

---

## 3. GET /api/scans/:id — Poll Scan Status

Retrieve the current status and metadata for a previously launched scan.

**Required permission:** `SCAN_READ`

### Request

```
GET /api/scans/:id
```

| Parameter | Type | Description                   |
| --------- | ---- | ----------------------------- |
| `id`      | uuid | The scan ID to query.         |

### Response

**200 OK** — returns the scan record with fields including:

| Field          | Type   | Description                                                        |
| -------------- | ------ | ------------------------------------------------------------------ |
| `id`           | uuid   | Scan ID.                                                           |
| `org_id`       | uuid   | Organisation ID.                                                   |
| `project_id`   | uuid   | Project ID.                                                        |
| `project_name` | string | Project name (joined from projects table).                         |
| `scan_type`    | string | The scan type (`dast`, `sast`, etc.).                              |
| `name`         | string | Human-readable name.                                               |
| `status`       | string | One of `queued`, `running`, `completed`, `failed`, `cancelled`, `paused`. |
| `options`      | object | Scan options as originally submitted.                              |
| `started_at`   | string | ISO 8601 timestamp when the scan was queued.                       |
| `completed_at` | string | ISO 8601 timestamp when the scan finished (null if not completed). |
| `created_at`   | string | ISO 8601 timestamp.                                                |
| `updated_at`   | string | ISO 8601 timestamp.                                                |

### cURL Example

```bash
SCAN_ID="a1b2c3d4-e5f6-7890-abcd-ef1234567890"

curl -s http://localhost:3000/api/scans/$SCAN_ID \
  -H 'X-API-Key: $API_KEY' | jq .
```

---

## 4. GET /api/scans/:id/findings — Get Scan Findings

Retrieve all findings produced by a completed scan.

**Required permission:** `SCAN_READ`

### Request

```
GET /api/scans/:id/findings
```

| Parameter | Type | Description                   |
| --------- | ---- | ----------------------------- |
| `id`      | uuid | The scan ID.                  |

### Response

**200 OK**

```json
{
  "data": [
    {
      "id": "f1e2d3c4-b5a6-7890-1234-567890abcdef",
      "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "rule_id": "xss-reflected",
      "severity": "high",
      "severity_rank": 3,
      "title": "Reflected XSS",
      "description": "User input is reflected in the response without sanitisation.",
      "location": "https://staging.example.com/search?q=<payload>",
      "cwe_id": "CWE-79",
      "created_at": "2025-01-15T10:30:00Z"
    }
  ],
  "total": 1
}
```

Results are ordered by severity (most critical first), then by creation date.

### cURL Example

```bash
SCAN_ID="a1b2c3d4-e5f6-7890-abcd-ef1234567890"

curl -s http://localhost:3000/api/scans/$SCAN_ID/findings \
  -H 'X-API-Key: $API_KEY' | jq .
```

---

## Complete DAST Workflow (Launch → Poll → Findings)

```bash
API_KEY="your-api-key-here"
BASE="http://localhost:3000"

# 1. Launch a DAST scan
SCAN_ID=$(curl -s -X POST $BASE/api/scans/launch \
  -H "X-API-Key: $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{
    "projectId": "e8f3a9b1-2c4d-5e6f-7a8b-9c0d1e2f3a4b",
    "scanType": "dast",
    "name": "My DAST scan",
    "options": {"targetUrl": "https://staging.example.com"}
  }' | jq -r '.id')

echo "Launched scan: $SCAN_ID"

# 2. Poll until completed
while true; do
  STATUS=$(curl -s $BASE/api/scans/$SCAN_ID \
    -H "X-API-Key: $API_KEY" | jq -r '.status')
  echo "Status: $STATUS"
  case "$STATUS" in
    completed|failed|cancelled) break ;;
    *) sleep 10 ;;
  esac
done

# 3. Retrieve findings
curl -s $BASE/api/scans/$SCAN_ID/findings \
  -H "X-API-Key: $API_KEY" | jq .
```

---

## Error Responses

All endpoints return standard HTTP error codes:

| Status | Meaning                                                                    |
| ------ | -------------------------------------------------------------------------- |
| 400    | Invalid request body or parameters. Check `details` in the response.       |
| 401    | Missing or invalid authentication.                                         |
| 403    | Authenticated but lacking the required permission.                         |
| 404    | Resource not found (e.g. invalid scan ID, project not found).              |
| 429    | Rate limit exceeded (120 req/min). Retry after the `Retry-After` header.  |

### Example Error Response

```json
{
  "error": "Invalid request",
  "details": {
    "fieldErrors": {
      "filename": ["Required"],
      "content": ["Expected string, received number"]
    }
  }
}
```

---

## Supported Languages (SAST)

The language is auto-detected from the file extension in `filename`. You can override it with the `language` field. Supported extensions include:

`.js`, `.ts`, `.jsx`, `.tsx`, `.py`, `.java`, `.go`, `.rb`, `.php`, `.c`, `.cpp`, `.cs`, `.swift`, `.kt`, `.rs`, `.scala`, and others.
