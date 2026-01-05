import math
from collections import Counter
from config import MAX_LABEL_LENGTH, ENTROPY_THRESHOLD


def calculate_entropy(value: str) -> float:
    """
    Calculate Shannon entropy of a string.
    High entropy may indicate encoded or exfiltration data.
    """
    if not value:
        return 0

    probabilities = [
        count / len(value) for count in Counter(value).values()
    ]

    return -sum(p * math.log2(p) for p in probabilities)


def analyze_dns_query(query_name: str) -> bool:
    """
    Returns True if the DNS query looks suspicious.
    """
    labels = query_name.split(".")

    for label in labels:
        entropy = calculate_entropy(label)

        if len(label) > MAX_LABEL_LENGTH:
            return True

        if entropy > ENTROPY_THRESHOLD:
            return True

    return False


def scan_dns_logs(dns_queries: list):
    print("\n[+] Analyzing DNS logs for tunneling behavior...\n")

    for query in dns_queries:
        if analyze_dns_query(query):
            print(f"[ALERT] Suspicious DNS query detected: {query}")
