from flask import Flask, render_template, request, redirect, url_for
import os
from parsers.kali_parser import parse_kali_log
from parsers.firewall_parser import parse_firewall_log

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'logs_sample'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Max 16MB dosya izni
ALLOWED_EXTENSIONS = {'txt', 'log'}

PROCESSED_LOGS = []

def allowed_file(filename):
    """Dosya uzantısı .txt veya .log mu diye bakar."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def detect_log_type(file_content):
    """
    Dosya içeriğine bakarak tür tespiti yapar.
    Eskisi gibi varsayım yapmaz, emin değilse None döndürür.
    """
    # İlk 10 satırı birleştirip analiz edelim (daha isabetli olur)
    snippet = "\n".join(file_content[:10]).lower()

    # 1. Firewall İmzaları
    if "devname=" in snippet or "srcip=" in snippet or "type=traffic" in snippet:
        return "FIREWALL"
    
    # 2. Kali/Linux İmzaları (Strict Mode)
    # Sadece bu kelimeler varsa Kali kabul et. Yoksa reddet.
    linux_keywords = ["sshd", "sudo", "su(", "kernel:", "auth.log", "syslog", "pam_unix", "session opened"]
    for keyword in linux_keywords:
        if keyword in snippet:
            return "KALI"
            
    # 3. Hiçbir şeye benzemiyorsa
    return None

@app.route('/')
def index():
    error_message = request.args.get('error') # URL'den hata mesajını al
    
    # Grafik verisi hazırlığı
    severity_counts = {
        "CRITICAL": len([l for l in PROCESSED_LOGS if l['priority'] == 'CRITICAL']),
        "HIGH": len([l for l in PROCESSED_LOGS if l['priority'] == 'HIGH']),
        "LOW": len([l for l in PROCESSED_LOGS if l['priority'] == 'LOW']),
    }
    
    stats = {
        "total": len(PROCESSED_LOGS),
        "critical": severity_counts["CRITICAL"],
        "fp_reduced": severity_counts["LOW"]
    }
    
    return render_template('index.html', 
                           logs=PROCESSED_LOGS, 
                           stats=stats,
                           chart_data=severity_counts,
                           error=error_message) # Hatayı HTML'e gönder

@app.route('/upload', methods=['POST'])
def upload_file():
    # 1. Dosya var mı?
    if 'file' not in request.files:
        return redirect(url_for('index', error="Dosya seçilmedi."))
    
    file = request.files['file']
    
    # 2. Dosya adı boş mu?
    if file.filename == '':
        return redirect(url_for('index', error="Dosya adı boş olamaz."))

    # 3. Uzantı kontrolü (.exe, .pdf engelleme)
    if not allowed_file(file.filename):
        return redirect(url_for('index', error="Geçersiz dosya türü! Sadece .log ve .txt kabul edilir."))
    
    # Klasör kontrolü
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(file_path)
    
    # 4. Dosya Okuma ve Binary Kontrolü
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            file_content = f.read().splitlines()
    except UnicodeDecodeError:
        try:
            with open(file_path, 'r', encoding='latin-1') as f:
                file_content = f.read().splitlines()
        except:
            return redirect(url_for('index', error="Dosya okunamadı! Binary veya bozuk dosya olabilir."))

    # 5. İçerik Boş mu?
    if not file_content:
        return redirect(url_for('index', error="Yüklenen dosya boş!"))

    # 6. Log Türü Tespiti (En Kritik Kısım)
    log_type = detect_log_type(file_content)
    
    if log_type is None:
        return redirect(url_for('index', error="Tanımlanamayan Log Formatı! Bu sistem sadece Kali Linux ve Firewall loglarını destekler."))

    # Her şey yolundaysa işle
    PROCESSED_LOGS.clear()
    for line in file_content:
        if line.strip():
            if log_type == "FIREWALL":
                parsed_data = parse_firewall_log(line)
            else:
                parsed_data = parse_kali_log(line)
            PROCESSED_LOGS.append(parsed_data)
            
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)