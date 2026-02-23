import math

def calculate_entropy(filepath):
    """Calculate Shannon entropy of a file. High entropy = possibly encrypted."""
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        if not data:
            return 0
        
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        
        entropy = 0
        length = len(data)
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return round(entropy, 4)
    except Exception:
        return -1

def is_suspicious_entropy(filepath, threshold=7.2):
    """Files with entropy > 7.2 out of 8 are likely encrypted."""
    entropy = calculate_entropy(filepath)
    return entropy > threshold, entropy