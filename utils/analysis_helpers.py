# threatpeek/utils/analysis_helpers.py
import math
from typing import Optional
from config import config

def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0
    length = len(data)
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    for c in freq:
        p = freq[c] / length
        entropy -= p * math.log2(p)
    return entropy

def is_high_entropy(s: str, threshold: Optional[float] = None) -> bool:
    """Returns True if the Shannon entropy of s meets or exceeds the threshold.
    Defaults to config.ENTROPY_THRESHOLD when no threshold is provided.
    """
    if threshold is None:
        threshold = config.ENTROPY_THRESHOLD
    return shannon_entropy(s) >= threshold
