import subprocess
import re
from collections import defaultdict
import time
import geoip2.database

# Configuration
LOG_FILE = "/var/log/nginx/access.log"
GEOIP_CITY_DB_PATH = "/usr/local/share/GeoIP/GeoLite2-City.mmdb"
GEOIP_ASN_DB_PATH = "/usr/local/share/GeoIP/GeoLite2-ASN.mmdb"
BYTES_TO_MBITS = 8 / 1_000_000
METRICS_FILE = "/var/www/html/metrics"
UPDATE_INTERVAL = 5  # seconds
INACTIVITY_TIMEOUT = 3600  # seconds

# Initialize GeoIP readers
geoip_city_reader = geoip2.database.Reader(GEOIP_CITY_DB_PATH)
geoip_asn_reader = geoip2.database.Reader(GEOIP_ASN_DB_PATH)

# Track IP activity
ip_activity = defaultdict(lambda: {'last_seen': 0, 'active': False, 'bandwidth': 0})

def tail_log_file():
    """Tail the Nginx log file continuously"""
    process = subprocess.Popen(['tail', '-F', LOG_FILE],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    while True:
        line = process.stdout.readline()
        if line:
            yield line
        else:
            time.sleep(0.1)

def parse_log_entry(log_entry):
    """Parse log entry with support for both HTTP and HTTPS"""
    # Pola regex yang lebih robust untuk format log Nginx standar
    # $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
    pattern = (
        r'^(?P<ip>\d+\.\d+\.\d+\.\d+)\s-\s-\s\[.*?\]\s'
        r'"(?P<method>\w+)\s(?P<url>.+?)\sHTTP/\d\.\d"\s'
        r'(?P<status>\d+)\s(?P<bytes>\d+)'
    )

    try:
        decoded_entry = log_entry.decode('utf-8')
        match = re.match(pattern, decoded_entry)
        if match:
            url = match.group('url')
            # Jika URL sudah memiliki protokol, ekstrak hanya path-nya
            if url.startswith(('http://', 'https://')):
                # Remove protocol and domain, keep path only
                path = '/' + '/'.join(url.split('/')[3:])
            else:
                path = url

            return (
                match.group('ip'),
                path,
                int(match.group('bytes')),
                match.group('method')
            )
    except Exception as e:
        print(f"Error parsing log entry: {e}")

    return None, None, 0, None

def extract_server_origin_and_channel(path):
    """
    Extract server origin and channel name from URL path.
    Example path: /astra-cibi/local/play/channel4/index.m3u8
    Returns tuple (server_origin, channel_name)
    """
    # Regex untuk menangkap server origin (segmen pertama)
    # dan channel name (segmen setelah server origin dan subfolder opsional)
    pattern = (
        r'^\/(?P<server_origin>[^\/]+)\/'                  # server origin
        r'(?:local\/)?'                                    # optional 'local/'
        r'(?:play\/)?'                                     # optional 'play/'
        r'(?P<channel>[^\/\.]+)'                          # channel name (exclude extensions)
    )

    match = re.match(pattern, path)
    if match:
        return match.group('server_origin'), match.group('channel')
    return None, None

def get_geoip_info(ip):
    """Get GeoIP information for an IP address (City + ASN)"""
    country = "Unknown"
    city = "Unknown"
    lat = 0
    lon = 0
    asn_number = 0
    asn_organization = "Unknown"
    isp = "Unknown"

    try:
        # Get City information
        response_city = geoip_city_reader.city(ip)
        country = response_city.country.name if response_city.country.name else "Unknown"
        city = response_city.city.name if response_city.city.name else "Unknown"
        lat = response_city.location.latitude if response_city.location.latitude else 0
        lon = response_city.location.longitude if response_city.location.longitude else 0

        # Get ASN information
        response_asn = geoip_asn_reader.asn(ip)
        asn_number = response_asn.autonomous_system_number if response_asn.autonomous_system_number else 0
        asn_organization = response_asn.autonomous_system_organization if response_asn.autonomous_system_organization else "Unknown"

        # ISP bisa diambil dari ASN organization atau dari database lain
        isp = asn_organization

    except Exception as e:
        print(f"GeoIP error for {ip}: {e}")

    return country, city, lat, lon, asn_number, asn_organization, isp

def sanitize_label_value(value):
    """Sanitize label values for Prometheus metrics"""
    if value is None:
        return "unknown"
    # Escape backslashes, double quotes, and newlines
    return str(value).replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')

def write_metrics(metrics, current_time):
    """Write all metrics to the metrics file"""
    try:
        with open(METRICS_FILE, 'w') as f:
            # IP request counts
            f.write('# HELP nginx_ip_request_count Total requests per IP\n')
            f.write('# TYPE nginx_ip_request_count counter\n')
            for ip, count in metrics['ip_requests'].items():
                sanitized_ip = sanitize_label_value(ip)
                f.write(f'nginx_ip_request_count{{ip="{sanitized_ip}"}} {count}\n')

            # IP bandwidth - filter inactive IPs
            f.write('\n# HELP nginx_ip_bandwidth Bandwidth per IP (Mbps)\n')
            f.write('# TYPE nginx_ip_bandwidth gauge\n')

            # Hanya hitung bandwidth untuk IP yang aktif
            for ip, data in metrics['ip_bandwidth'].items():
                if ip in ip_activity:
                    time_since_last_seen = current_time - ip_activity[ip]['last_seen']
                    if time_since_last_seen <= INACTIVITY_TIMEOUT and data['bytes'] > 0:
                        bandwidth_mbps = (data['bytes'] / UPDATE_INTERVAL) * BYTES_TO_MBITS
                        country, city, lat, lon, asn_number, asn_organization, isp = get_geoip_info(ip)

                        sanitized_ip = sanitize_label_value(ip)
                        sanitized_country = sanitize_label_value(country)
                        sanitized_city = sanitize_label_value(city)
                        sanitized_asn_org = sanitize_label_value(asn_organization)
                        sanitized_isp = sanitize_label_value(isp)

                        f.write(
                            f'nginx_ip_bandwidth{{ip="{sanitized_ip}",country="{sanitized_country}",'
                            f'city="{sanitized_city}",asn="{asn_number}",asn_org="{sanitized_asn_org}",'
                            f'isp="{sanitized_isp}",latitude="{lat}",longitude="{lon}"}} '
                            f'{bandwidth_mbps:.6f}\n'
                        )

            # Channel bandwidth - ditambahkan
            f.write('\n# HELP nginx_channel_bandwidth Bandwidth per channel (Mbps)\n')
            f.write('# TYPE nginx_channel_bandwidth gauge\n')

            # Hitung total bandwidth per channel
            channel_bandwidth_totals = defaultdict(float)
            channel_server_origin_bandwidth = defaultdict(lambda: defaultdict(float))

            # Kumpulkan bandwidth per channel
            for (server_origin, channel), data in metrics['channel_server_origin_bandwidth'].items():
                # Hanya hitung untuk channel yang memiliki traffic aktif
                active_ips = {ip for ip in data['ips'] if ip in ip_activity and
                             (current_time - ip_activity[ip]['last_seen']) <= INACTIVITY_TIMEOUT}

                if active_ips and data['bytes'] > 0:
                    bandwidth_mbps = (data['bytes'] / UPDATE_INTERVAL) * BYTES_TO_MBITS
                    channel_bandwidth_totals[channel] += bandwidth_mbps
                    channel_server_origin_bandwidth[channel][server_origin] += bandwidth_mbps

            # Tulis bandwidth total per channel
            for channel, bandwidth in channel_bandwidth_totals.items():
                sanitized_channel = sanitize_label_value(channel)
                f.write(f'nginx_channel_bandwidth{{channel="{sanitized_channel}"}} {bandwidth:.6f}\n')

            # Bandwidth per channel dengan server_origin
            f.write('\n# HELP nginx_channel_server_origin_bandwidth Bandwidth per channel with server origin (Mbps)\n')
            f.write('# TYPE nginx_channel_server_origin_bandwidth gauge\n')

            for channel, server_origins in channel_server_origin_bandwidth.items():
                for server_origin, bandwidth in server_origins.items():
                    if bandwidth > 0:
                        sanitized_channel = sanitize_label_value(channel)
                        sanitized_server_origin = sanitize_label_value(server_origin)
                        f.write(f'nginx_channel_server_origin_bandwidth{{channel="{sanitized_channel}",server_origin="{sanitized_server_origin}"}} {bandwidth:.6f}\n')

            # Channel traffic - dengan server_origin
            f.write('\n# HELP nginx_channel_traffic IPs per channel\n')
            f.write('# TYPE nginx_channel_traffic gauge\n')

            # Struktur untuk menyimpan channel dengan server_origin yang sesuai
            channel_metrics = defaultdict(lambda: {'ips': set(), 'server_origin': defaultdict(set)})

            # Kumpulkan data channel dengan server_origin
            for (server_origin, channel), ips in metrics['channel_server_origin_access'].items():
                channel_metrics[channel]['ips'].update(ips)
                for ip in ips:
                    channel_metrics[channel]['server_origin'][server_origin].add(ip)

            for channel, data in channel_metrics.items():
                # Filter hanya IP yang aktif
                active_ips = {ip for ip in data['ips'] if ip in ip_activity and
                             (current_time - ip_activity[ip]['last_seen']) <= INACTIVITY_TIMEOUT}

                if active_ips:
                    sanitized_channel = sanitize_label_value(channel)
                    f.write(f'nginx_channel_traffic{{channel="{sanitized_channel}"}} {len(active_ips)}\n')

            # Channel IP access dengan server_origin (dengan info ASN)
            f.write('\n# HELP nginx_channel_ip_access IP access per channel with server origin and ASN info\n')
            f.write('# TYPE nginx_channel_ip_access gauge\n')

            for (server_origin, channel), ips in metrics['channel_server_origin_access'].items():
                # Filter hanya IP yang aktif
                active_ips = {ip for ip in ips if ip in ip_activity and
                             (current_time - ip_activity[ip]['last_seen']) <= INACTIVITY_TIMEOUT}

                if active_ips:
                    sanitized_channel = sanitize_label_value(channel)
                    sanitized_server_origin = sanitize_label_value(server_origin)

                    for ip in active_ips:
                        country, city, lat, lon, asn_number, asn_organization, isp = get_geoip_info(ip)
                        sanitized_ip = sanitize_label_value(ip)
                        sanitized_country = sanitize_label_value(country)
                        sanitized_city = sanitize_label_value(city)
                        sanitized_asn_org = sanitize_label_value(asn_organization)
                        sanitized_isp = sanitize_label_value(isp)

                        f.write(
                            f'nginx_channel_ip_access{{channel="{sanitized_channel}",'
                            f'server_origin="{sanitized_server_origin}",ip="{sanitized_ip}",'
                            f'country="{sanitized_country}",city="{sanitized_city}",asn="{asn_number}",'
                            f'asn_org="{sanitized_asn_org}",isp="{sanitized_isp}",latitude="{lat}",'
                            f'longitude="{lon}"}} 1\n'
                        )

            # Server origin traffic
            f.write('\n# HELP nginx_server_origin_traffic IPs per server_origin\n')
            f.write('# TYPE nginx_server_origin_traffic gauge\n')
            for server_origin, ips in metrics['server_origin_access'].items():
                # Filter hanya IP yang aktif
                active_ips = {ip for ip in ips if ip in ip_activity and
                             (current_time - ip_activity[ip]['last_seen']) <= INACTIVITY_TIMEOUT}
                if active_ips:
                    sanitized_server_origin = sanitize_label_value(server_origin)
                    f.write(f'nginx_server_origin_traffic{{server_origin="{sanitized_server_origin}"}} {len(active_ips)}\n')

            # Server origin bandwidth
            f.write('\n# HELP nginx_server_origin_bandwidth Bandwidth per server origin (Mbps)\n')
            f.write('# TYPE nginx_server_origin_bandwidth gauge\n')

            for server_origin, data in metrics['server_origin_bandwidth'].items():
                # Filter hanya IP yang aktif
                active_ips = {ip for ip in data['ips'] if ip in ip_activity and
                             (current_time - ip_activity[ip]['last_seen']) <= INACTIVITY_TIMEOUT}

                if active_ips and data['bytes'] > 0:
                    bandwidth_mbps = (data['bytes'] / UPDATE_INTERVAL) * BYTES_TO_MBITS
                    sanitized_server_origin = sanitize_label_value(server_origin)
                    f.write(f'nginx_server_origin_bandwidth{{server_origin="{sanitized_server_origin}"}} {bandwidth_mbps:.6f}\n')

            # Server origin IP access (dengan info ASN)
            f.write('\n# HELP nginx_server_origin_ip_access IP access per server origin with ASN info\n')
            f.write('# TYPE nginx_server_origin_ip_access gauge\n')
            for server_origin, ips in metrics['server_origin_access'].items():
                # Filter hanya IP yang aktif
                active_ips = {ip for ip in ips if ip in ip_activity and
                             (current_time - ip_activity[ip]['last_seen']) <= INACTIVITY_TIMEOUT}

                if active_ips:
                    sanitized_server_origin = sanitize_label_value(server_origin)

                    for ip in active_ips:
                        country, city, lat, lon, asn_number, asn_organization, isp = get_geoip_info(ip)
                        sanitized_ip = sanitize_label_value(ip)
                        sanitized_country = sanitize_label_value(country)
                        sanitized_city = sanitize_label_value(city)
                        sanitized_asn_org = sanitize_label_value(asn_organization)
                        sanitized_isp = sanitize_label_value(isp)

                        f.write(
                            f'nginx_server_origin_ip_access{{server_origin="{sanitized_server_origin}",ip="{sanitized_ip}",'
                            f'country="{sanitized_country}",city="{sanitized_city}",asn="{asn_number}",'
                            f'asn_org="{sanitized_asn_org}",isp="{sanitized_isp}",latitude="{lat}",'
                            f'longitude="{lon}"}} 1\n'
                        )

            # ASN-specific metrics
            f.write('\n# HELP nginx_asn_bandwidth Bandwidth per ASN (Mbps)\n')
            f.write('# TYPE nginx_asn_bandwidth gauge\n')

            # Hitung bandwidth per ASN
            asn_bandwidth = defaultdict(float)
            asn_ip_count = defaultdict(set)

            for ip, data in metrics['ip_bandwidth'].items():
                if ip in ip_activity:
                    time_since_last_seen = current_time - ip_activity[ip]['last_seen']
                    if time_since_last_seen <= INACTIVITY_TIMEOUT and data['bytes'] > 0:
                        country, city, lat, lon, asn_number, asn_organization, isp = get_geoip_info(ip)
                        if asn_number > 0:
                            bandwidth_mbps = (data['bytes'] / UPDATE_INTERVAL) * BYTES_TO_MBITS
                            asn_bandwidth[asn_number] += bandwidth_mbps
                            asn_ip_count[asn_number].add(ip)

            for asn_number, bandwidth in asn_bandwidth.items():
                # Coba dapatkan info ASN dari IP pertama
                sample_ip = next(iter(asn_ip_count[asn_number])) if asn_ip_count[asn_number] else None
                if sample_ip:
                    country, city, lat, lon, _, asn_organization, isp = get_geoip_info(sample_ip)
                    sanitized_asn_org = sanitize_label_value(asn_organization)
                    sanitized_isp = sanitize_label_value(isp)

                    f.write(f'nginx_asn_bandwidth{{asn="{asn_number}",asn_org="{sanitized_asn_org}",isp="{sanitized_isp}"}} {bandwidth:.6f}\n')

            # ASN IP count
            f.write('\n# HELP nginx_asn_ip_count Number of unique IPs per ASN\n')
            f.write('# TYPE nginx_asn_ip_count gauge\n')

            for asn_number, ips in asn_ip_count.items():
                active_ips = {ip for ip in ips if ip in ip_activity and
                             (current_time - ip_activity[ip]['last_seen']) <= INACTIVITY_TIMEOUT}

                if active_ips:
                    sample_ip = next(iter(active_ips))
                    country, city, lat, lon, _, asn_organization, isp = get_geoip_info(sample_ip)
                    sanitized_asn_org = sanitize_label_value(asn_organization)
                    sanitized_isp = sanitize_label_value(isp)

                    f.write(f'nginx_asn_ip_count{{asn="{asn_number}",asn_org="{sanitized_asn_org}",isp="{sanitized_isp}"}} {len(active_ips)}\n')

    except Exception as e:
        print(f"Error writing metrics: {e}")

def monitor_nginx_traffic():
    """Main monitoring function"""
    print(f"Monitoring Nginx traffic from {LOG_FILE}...")

    metrics = {
        'ip_requests': defaultdict(int),
        'ip_bandwidth': defaultdict(lambda: {'bytes': 0}),
        'channel_access': defaultdict(set),  # Untuk backward compatibility
        'server_origin_access': defaultdict(set),
        'channel_server_origin_access': defaultdict(set),  # Untuk menggabungkan channel dan server_origin
        'channel_server_origin_bandwidth': defaultdict(lambda: {'bytes': 0, 'ips': set()}),  # Bandwidth per channel dengan server_origin
        'server_origin_bandwidth': defaultdict(lambda: {'bytes': 0, 'ips': set()}),  # Bandwidth per server_origin
        'channel_bandwidth': defaultdict(lambda: {'bytes': 0, 'ips': set()})  # Bandwidth per channel (total)
    }

    last_update = time.time()
    last_cleanup = time.time()

    try:
        for log_entry in tail_log_file():
            ip, path, bytes_transferred, method = parse_log_entry(log_entry)
            current_time = time.time()

            if ip and path:
                # Update IP activity
                if not ip_activity[ip]['active']:
                    ip_activity[ip]['active'] = True
                    ip_activity[ip]['bandwidth'] = 0
                    # Pastikan entry ada di metrics['ip_bandwidth']
                    if ip not in metrics['ip_bandwidth']:
                        metrics['ip_bandwidth'][ip] = {'bytes': 0}

                metrics['ip_requests'][ip] += 1
                metrics['ip_bandwidth'][ip]['bytes'] += bytes_transferred
                ip_activity[ip]['last_seen'] = current_time
                ip_activity[ip]['bandwidth'] += bytes_transferred

                # Extract server origin and channel name
                server_origin, channel_name = extract_server_origin_and_channel(path)

                if channel_name:
                    metrics['channel_access'][channel_name].add(ip)
                    # Update bandwidth per channel
                    metrics['channel_bandwidth'][channel_name]['bytes'] += bytes_transferred
                    metrics['channel_bandwidth'][channel_name]['ips'].add(ip)

                if server_origin:
                    metrics['server_origin_access'][server_origin].add(ip)
                    # Update bandwidth per server_origin
                    metrics['server_origin_bandwidth'][server_origin]['bytes'] += bytes_transferred
                    metrics['server_origin_bandwidth'][server_origin]['ips'].add(ip)

                # Gabungkan channel dan server_origin untuk access dan bandwidth
                if server_origin and channel_name:
                    # Untuk access
                    key_access = (server_origin, channel_name)
                    metrics['channel_server_origin_access'][key_access].add(ip)

                    # Untuk bandwidth
                    key_bandwidth = (server_origin, channel_name)
                    metrics['channel_server_origin_bandwidth'][key_bandwidth]['bytes'] += bytes_transferred
                    metrics['channel_server_origin_bandwidth'][key_bandwidth]['ips'].add(ip)

            # Periodic update
            if current_time - last_update >= UPDATE_INTERVAL:
                # Check for inactive IPs dalam interval update
                for ip, data in list(ip_activity.items()):
                    if current_time - data['last_seen'] > UPDATE_INTERVAL:
                        if data['active']:
                            # Reset bandwidth untuk IP yang tidak aktif
                            if ip in metrics['ip_bandwidth']:
                                metrics['ip_bandwidth'][ip]['bytes'] = 0
                            ip_activity[ip]['active'] = False

                # Clean up IPs yang sudah tidak aktif untuk waktu lama
                if current_time - last_cleanup >= INACTIVITY_TIMEOUT:
                    inactive_ips = [ip for ip, data in ip_activity.items()
                                  if current_time - data['last_seen'] >= INACTIVITY_TIMEOUT]
                    for ip in inactive_ips:
                        del ip_activity[ip]
                        if ip in metrics['ip_bandwidth']:
                            del metrics['ip_bandwidth'][ip]
                    last_cleanup = current_time

                # Write metrics
                write_metrics(metrics, current_time)

                # Reset metrics untuk interval berikutnya
                metrics['ip_requests'].clear()

                # Reset bandwidth metrics, jangan hapus entry untuk yang masih aktif
                for ip in list(metrics['ip_bandwidth'].keys()):
                    metrics['ip_bandwidth'][ip]['bytes'] = 0

                # Reset bandwidth per channel
                for channel in list(metrics['channel_bandwidth'].keys()):
                    metrics['channel_bandwidth'][channel]['bytes'] = 0
                    metrics['channel_bandwidth'][channel]['ips'].clear()

                # Reset bandwidth per server_origin
                for server_origin in list(metrics['server_origin_bandwidth'].keys()):
                    metrics['server_origin_bandwidth'][server_origin]['bytes'] = 0
                    metrics['server_origin_bandwidth'][server_origin]['ips'].clear()

                # Reset bandwidth per channel dengan server_origin
                for key in list(metrics['channel_server_origin_bandwidth'].keys()):
                    metrics['channel_server_origin_bandwidth'][key]['bytes'] = 0
                    metrics['channel_server_origin_bandwidth'][key]['ips'].clear()

                # Reset access metrics
                metrics['channel_access'].clear()
                metrics['server_origin_access'].clear()
                metrics['channel_server_origin_access'].clear()

                last_update = current_time

    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
    except Exception as e:
        print(f"Monitoring error: {e}")
    finally:
        geoip_city_reader.close()
        geoip_asn_reader.close()

if __name__ == "__main__":
    monitor_nginx_traffic()
