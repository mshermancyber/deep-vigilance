# scan-sources

The default target for `SCAN_SOURCE_DIR`, mounted into every scanner as `/scan`
(read-only). Put the code you want scanned here, or point `SCAN_SOURCE_DIR` at it.

Keep this narrow. A scan launched without an explicit `options.targetPath` defaults
to all of `/scan`, so a broad mount means a scan that runs for hours.

This placeholder only keeps the directory in git; its contents are ignored.
