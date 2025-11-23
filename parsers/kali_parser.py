import re

def parse_kali_log(line):
    """
    Kali Linux auth.log satırlarını analiz eder.
    """
    # 1. Regex Tanımları
    time_regex = r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})"
    ip_regex = r"rhost=([\w\.\-]+)"
    
    timestamp_match = re.search(time_regex, line)
    timestamp = timestamp_match.group(1) if timestamp_match else "Unknown Time"
    
    ip_match = re.search(ip_regex, line)
    ip = ip_match.group(1) if ip_match else "-"

    # 2. Kural ve Skorlama Motoru
    priority = "LOW"
    event_type = "System Event"

    # Kritik Kurallar (Brute Force vb.)
    if "authentication failure" in line or "check pass; user unknown" in line:
        priority = "CRITICAL"
        event_type = "Brute Force Attempt"
        if ip == "-": ip = "Unknown Attacker"

    # Yüksek Öncelikli Kurallar
    elif "ALERT exited abnormally" in line:
        priority = "HIGH"
        event_type = "Service Error"
        ip = "Localhost"

    # False Positive (Gürültü) Kuralları
    elif "session opened" in line or "session closed" in line:
        priority = "LOW"
        event_type = "Routine Session"
        ip = "Localhost"
        if "cyrus" in line or "news" in line:
            event_type = "Automated Task (Clean)"

    return {
        "timestamp": timestamp,
        "source": "Kali Linux",
        "event": event_type,
        "ip": ip,
        "priority": priority,
        "raw": line
    }