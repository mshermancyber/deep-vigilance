# Deep Vigilance GitHub Action

Run security scans against the Deep Vigilance platform and gate your CI builds on the results.

## Usage

```yaml
name: Security Scan
on:
  push:
    branches: [main]
  pull_request:

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Deep Vigilance Scan
        id: scan
        uses: your-org/deep-vigilance-action@v1
        # Or reference a local path:
        # uses: ./cicd/github-action
        with:
          api-url: ${{ secrets.DV_API_URL }}
          api-email: ${{ secrets.DV_EMAIL }}
          api-password: ${{ secrets.DV_PASSWORD }}
          project-id: ${{ secrets.DV_PROJECT_ID }}
          scan-type: sast          # sast | dast | api | sca | full
          fail-on: high            # critical | high | medium | low | none
          timeout: 600

      - name: Show results
        if: always()
        run: |
          echo "Scan ID: ${{ steps.scan.outputs.scan-id }}"
          echo "Total findings: ${{ steps.scan.outputs.findings-total }}"
          echo "Critical: ${{ steps.scan.outputs.findings-critical }}"
          echo "High: ${{ steps.scan.outputs.findings-high }}"
```

## Inputs

| Input          | Required | Default | Description                                          |
|----------------|----------|---------|------------------------------------------------------|
| `api-url`      | Yes      |         | Base URL of the Deep Vigilance API                   |
| `api-email`    | Yes      |         | Email for API authentication                         |
| `api-password` | Yes      |         | Password for API authentication                      |
| `project-id`   | Yes      |         | UUID of the project to scan                          |
| `scan-type`    | No       | `full`  | Scan type: `sast`, `dast`, `api`, `sca`, `full`     |
| `fail-on`      | No       | `high`  | Fail threshold: `critical`, `high`, `medium`, `low`, `none` |
| `timeout`      | No       | `600`   | Maximum seconds to wait for scan completion          |
| `branch`       | No       |         | Branch to scan (defaults to current ref)             |

## Outputs

| Output              | Description                  |
|---------------------|------------------------------|
| `scan-id`           | UUID of the launched scan    |
| `findings-total`    | Total number of findings     |
| `findings-critical` | Number of critical findings  |
| `findings-high`     | Number of high findings      |
| `status`            | Scan completion status       |

## Requirements

The runner must have `curl` and `jq` available (both are pre-installed on `ubuntu-latest`).

## Secrets Setup

Add these secrets in your repository or organization settings:

- `DV_API_URL` - e.g. `https://security.yourcompany.com`
- `DV_EMAIL` - service account email
- `DV_PASSWORD` - service account password
- `DV_PROJECT_ID` - UUID from the Deep Vigilance project settings
