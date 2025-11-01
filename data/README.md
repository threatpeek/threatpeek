# Tranco Snapshot

Place a Tranco top-1M snapshot CSV here to enable offline global rank lookups.

Accepted formats (first two columns will be parsed):
- rank,domain
- domain,rank

Defaults
- Path: data/tranco_top1m.csv (can override via TRANCO_SNAPSHOT_PATH)
- Max rank loaded: 1,000,000 (override via TRANCO_MAX_RANK)

Get a snapshot from https://tranco-list.eu/ (export CSV) and save as `tranco_top1m.csv` in this directory.
