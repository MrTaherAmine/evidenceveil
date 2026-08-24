# Format Support

Core v1 sanitization supports text/logs, RFC5424-like syslog, CEF, LEEF, JSON, JSONL/NDJSON, CSV, TSV and gzip text. Safe ZIP/TAR extraction primitives are included for controlled developer/library use, but direct archive sanitization is not wired into the v1.0 CLI. EVTX and Parquet are recognized as file types but are not parsed or sanitized in v1.0. Binary EVTX rewriting and PCAP rewriting are not claimed.
