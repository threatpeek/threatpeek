# threatpeek/utils/analysis_helpers.py
import math

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

def is_high_entropy(s: str, threshold: float = 4.5) -> bool:
    return shannon_entropy(s) >= threshold
