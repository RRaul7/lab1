import re
import json
import csv
from collections import defaultdict

log_file = "server_logs.txt"
html_file = "index.html"

# Regex əsaslı log analizi
log_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?)" (\d+) \d+')
ip_failures = defaultdict(int)
log_data = []

# Log faylının oxuyunub məlumat çıxarışı
with open(log_file, "r") as f:
    for line in f:
        match = log_pattern.match(line)
        if match:
            ip, date, method, status = match.groups()
            log_data.append({"IP": ip, "Date": date, "Method": method, "Status": status})
            if status == "401":  # Uğursuz giriş statusu
                ip_failures[ip] += 1

# 5-dən çox uğursuz giriş cəhdi olan IP-ləri JSON faylında yazmaq
failed_logins = {ip: count for ip, count in ip_failures.items() if count >= 5}
with open("failed_logins.json", "w") as f:
    json.dump(failed_logins, f, indent=4)

# Uğursuz girişlərin sayını mətn faylına yazmaq
with open("log_analysis.txt", "w") as f:
    for ip, count in ip_failures.items():
        f.write(f"{ip}: {count} failed attempts\n")

# CSV faylında uğursuz girişlərin cəminin göstərilməsi
with open("log_analysis.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["IP", "Date", "Method", "Failed Attempts"])
    for entry in log_data:
        ip = entry["IP"]
        failed_attempts = ip_failures.get(ip, 0)  # Cari IP üçün uğursuz girişlərin sayı
        writer.writerow([ip, entry["Date"], entry["Method"], failed_attempts])

# HTML-dən təhdid IP-ləri çıxarmaq
threat_ips = []
with open(html_file, "r") as f:
    for line in f:
        if "td" in line:
            match = re.search(r'>(\d+\.\d+\.\d+\.\d+)<', line)
            if match:
                threat_ips.append(match.group(1))

# Təhdid IP-lərini JSON faylına yazmaq
with open("threat_ips.json", "w") as f:
    json.dump(threat_ips, f, indent=4)

# Təhlükəsizlik məlumatlarını birləşdirmək
combined_data = {"Failed Logins": failed_logins, "Threat IPs": threat_ips}
with open("combined_security_data.json", "w") as f:
    json.dump(combined_data, f, indent=4)

print("Skript uğurla icra olundu")
