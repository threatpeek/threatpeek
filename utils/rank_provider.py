# utils/rank_provider.py
import csv
import os
from typing import Optional, Tuple

try:
    import tldextract  # optional
except ImportError:  # pragma: no cover
    tldextract = None  # type: ignore

from config import config

_ranks: dict[str, int] = {}
_loaded_path: Optional[str] = None
_loaded_mtime: Optional[float] = None


def _load_snapshot_if_needed() -> bool:
    if not config.RANKING_ENABLED:
        return False

    path = config.TRANCO_SNAPSHOT_PATH
    if not path or not os.path.exists(path):
        return False

    global _loaded_path, _loaded_mtime, _ranks
    try:
        mtime = os.path.getmtime(path)
        if _loaded_path == path and _loaded_mtime == mtime and _ranks:
            return True  # already loaded and unchanged

        ranks: dict[str, int] = {}
        with open(path, "r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row:
                    continue
                # Handle either [rank, domain] or [domain, rank]
                if len(row) >= 2:
                    a, b = row[0].strip(), row[1].strip()
                    if a.isdigit():
                        rank, domain = int(a), b.lower()
                    elif b.isdigit():
                        rank, domain = int(b), a.lower()
                    else:
                        continue
                else:
                    # Single-column list isn't supported
                    continue

                if rank <= 0 or rank > config.TRANCO_MAX_RANK:
                    continue
                # Keep the best (lowest) rank if duplicates
                prev = ranks.get(domain)
                if prev is None or rank < prev:
                    ranks[domain] = rank
        _ranks = ranks
        _loaded_path = path
        _loaded_mtime = mtime
        return True
    except Exception:
        # Fail closed: treat as not loaded
        _ranks = {}
        _loaded_path = None
        _loaded_mtime = None
        return False


def is_ready() -> bool:
    return _load_snapshot_if_needed() and bool(_ranks)


def registrable_domain(hostname: Optional[str]) -> Optional[str]:
    if not hostname:
        return None
    host = hostname.strip('.').lower()
    if not host:
        return None
    if tldextract:
        try:
            ext = tldextract.extract(host)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}".lower()
            return host
        except Exception:
            pass
    # Fallback naive heuristic: last two labels
    parts = host.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return host


def get_global_rank(host_or_domain: Optional[str]) -> Tuple[Optional[int], Optional[str]]:
    if not host_or_domain:
        return None, None
    if not _load_snapshot_if_needed():
        return None, None
    dom = registrable_domain(host_or_domain)
    if not dom:
        return None, None
    rank = _ranks.get(dom)
    if rank is None:
        return None, None
    return rank, "tranco"


def rank_bucket_for(rank: Optional[int]) -> Optional[str]:
    if rank is None:
        return None
    if rank <= 10_000:
        return "Top 10k"
    if rank <= 100_000:
        return "Top 100k"
    if rank <= 1_000_000:
        return "Top 1M"
    return "Not in Top 1M"
