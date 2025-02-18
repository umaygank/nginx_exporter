import subprocess
import re
from collections import defaultdict
import time
from datetime import datetime

#Path ke log file Nginx
LOG_FILE = "/var/log/nginx/access.log"

#Konstanta untuk konversi bytes ke Mbps
BYTES_TO_MBITS = 8 / 1_000_000

#Fungsi untuk membaca log file Nginx
def tail_log_file():
    process = subprocess.Popen(['tail', '-F', LOG_FILE], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    while True:
        line = process.stdout.readline()
        if line:
            yield line
        else:
            time.sleep(0.1)

#Fungsi untuk parsing log entry
def parse_log_entry(log_entry):
    # Contoh format log Nginx: 127.0.0.1 - - [10/Oct/2023:12:34:56 +0000] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0"
    pattern = r'^(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*\] "(?:GET|POST) (?P<path>.*?) HTTP/1\.\d" (?P<status>\d+) (?P<bytes>\d+)'
    match = re.match(pattern, log_entry.decode('utf-8'))
    if match:
        return match.group('ip'), match.group('path'), int(match.group('bytes'))
    return None, None, 0

#Fungsi untuk mengekstrak nama channel dari path
def extract_channel_name(path):
    match = re.search(r'\/([^\/]+)\/tracks-v1a1\/mono\.m3u8', path)
    if match:
        return match.group(1)
    return None

#Fungsi utama untuk monitoring
def monitor_nginx_traffic():
    ip_traffic = defaultdict(int)
    ip_bandwidth = defaultdict(int)
    channel_traffic = defaultdict(lambda: defaultdict(int))
    channel_ip_access = defaultdict(lambda: defaultdict(set))
    last_update_time = time.time()
    print("Monitoring Nginx traffic... Press Ctrl+C to stop.")
    try:
        for log_entry in tail_log_file():
            ip, path, bytes_transferred = parse_log_entry(log_entry)
            if ip:
                ip_traffic[ip] += 1
                ip_bandwidth[ip] += bytes_transferred
                channel_name = extract_channel_name(path)
                if channel_name:
                    channel_traffic[channel_name][ip] += bytes_transferred
                    channel_ip_access[channel_name][ip].add(ip)
            # Setiap 5 detik, tulis metrics ke file
            current_time = time.time()
            if current_time - last_update_time >= 5:
                with open('/var/www/html/metrics', 'w') as f:
                    f.write('# HELP nginx_ip_request_count Total request per IP\n')
                    f.write('# TYPE nginx_ip_request_count counter\n')
                    for ip, request_count in ip_traffic.items():
                        f.write(f'nginx_ip_request_count{{ip="{ip}"}} {request_count}\n')
                    f.write('# HELP nginx_ip_bandwidth Bandwidth per IP\n')
                    f.write('# TYPE nginx_ip_bandwidth gauge\n')
                    for ip, bandwidth in ip_bandwidth.items():
                        f.write(f'nginx_ip_bandwidth{{ip="{ip}"}} {(bandwidth / (current_time - last_update_time)) * BYTES_TO_MBITS}\n')
                    f.write('# HELP nginx_channel_traffic Total IP yang access setiap channel\n')
                    f.write('# TYPE nginx_channel_traffic gauge\n')
                    for channel_name, ip_traffic in channel_traffic.items():
                        f.write(f'# Channel: {channel_name}\n')
                        f.write(f'nginx_channel_traffic{{channel="{channel_name}"}} {len(ip_traffic)}\n')
                        for ip in channel_ip_access[channel_name]:
                            f.write(f'nginx_channel_ip_access{{channel="{channel_name}",ip="{ip}"}} 1\n')
                ip_traffic.clear()
                ip_bandwidth.clear()
                channel_traffic.clear()
                channel_ip_access.clear()
                last_update_time = current_time
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")

if __name__ == "__main__":
    monitor_nginx_traffic()
