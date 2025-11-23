import re

def parse_firewall_log(line):
    """
    Genel Firewall loglarını (Key-Value formatı) analiz eder.
    Örn: date=2023-10-01 action=deny src=192.168.1.5 dst=8.8.8.8
    """
    
    # 1. Veri Ayıklama (Key=Value yapısını çözer)
    # Bu regex satırdaki her 'anahtar=değer' ikilisini bulur
    kv_pattern = r"(\w+)=([^\s]+)"
    data = dict(re.findall(kv_pattern, line))
    
    # Zaman damgası bulmaya çalışalım (date + time)
    timestamp = f"{data.get('date', '')} {data.get('time', '')}".strip()
    if not timestamp:
        timestamp = "Unknown Time"
        
    # Kaynak IP
    ip = data.get('srcip', data.get('src', '-'))

    # 2. Kural ve Skorlama Motoru
    action = data.get('action', '').lower()
    msg = data.get('msg', '')
    
    priority = "LOW"
    event_type = "Traffic Flow"

    # KRİTİK: Engellenen zararlı trafik
    if action in ['deny', 'drop', 'block'] or "attack" in msg.lower():
        priority = "HIGH" # Firewall engellediyse olay kontrol altındadır ama Yüksektir.
        event_type = "Blocked Connection"
        
        # Eğer IPS (Saldırı Tespit) devreye girdiyse KRİTİK olur
        if "attack" in msg.lower() or "ips" in line.lower():
            priority = "CRITICAL"
            event_type = "IPS Attack Detected"

    # FALSE POSITIVE / GÜRÜLTÜ
    elif action in ['accept', 'allow', 'permit']:
        priority = "LOW"
        event_type = "Allowed Traffic"
    
    elif "heartbeat" in line.lower() or "update" in line.lower():
        event_type = "System Status"
        priority = "LOW"

    return {
        "timestamp": timestamp,
        "source": "Firewall",
        "event": event_type,
        "ip": ip,
        "priority": priority,
        "raw": line
    }