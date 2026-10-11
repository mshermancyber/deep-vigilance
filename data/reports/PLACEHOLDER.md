# data/reports

Generated report files, written as `<report-id>.<format>` by the report worker and
served by `GET /api/reports/:id/download`. The path is set by `REPORT_DIR`.

Files here are pruned by the retention job alongside their database rows once they
pass `RETAIN_REPORTS_DAYS`.

This placeholder only keeps the directory in git; its contents are ignored.
