import subprocess
import re
from collections import defaultdict
import time
import geoip2.database
import geoip2.errors

# Configuration
LOG_FILE = "/var/log/nginx/access.log"
GEOIP_CITY_DB_PATH = "/usr/local/share/GeoIP/GeoLite2-City.mmdb"
GEOIP_ASN_DB_PATH = "/usr/local/share/GeoIP/GeoLite2-ASN.mmdb"
BYTES_TO_MBITS = 8 / 1_000_000
METRICS_FILE = "/var/www/html/metrics"
UPDATE_INTERVAL = 5  # seconds
INACTIVITY_TIMEOUT = 3600  # seconds

# Initialize GeoIP readers
city_reader = geoip2.database.Reader(GEOIP_CITY_DB_PATH)
asn_reader = geoip2.database.Reader(GEOIP_ASN_DB_PATH)

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
    # Updated pattern to handle:
    # - Both HTTP and HTTPS protocols
    # - Different HTTP versions (1.0, 1.1)
    # - Various request methods
    pattern = (
        r'^(?P<ip>\d+\.\d+\.\d+\.\d+)\s-\s-\s\[.*?\]\s'
        r'"(?P<method>\w+)\s(?P<url>.+?)\sHTTP/\d\.\d"\s'
        r'(?P<status>\d+)\s(?P<bytes>\d+)'
    )

    try:
        decoded_entry = log_entry.decode('utf-8')
        match = re.match(pattern, decoded_entry)
        if match:
            # Extract the path from URL (handles both http:// and https://)
            url = match.group('url')
            if url.startswith(('http://', 'https://')):
                # Remove protocol and domain
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

def extract_channel_name(path):
    """Extract channel name from path (supports m3u8, mpegts, and mpd)"""
    patterns = [
        r'\/([^\/]+)\/tracks-v1a\d+(?:\/|a\d+\/)mono\.m3u8',  # HLS tracks
        r'\/([^\/]+)\/index\.mpd',  # DASH manifest
        r'\/([^\/]+)\/mpegts',  # MPEG-TS stream
        r'\/([^\/]+)\/.*\.m3u8',  # Any HLS manifest
        r'\/([^\/]+)\/.*\.ts',  # HLS segments
        r'\/([^\/]+)\/.*\.mpd',  # Any DASH manifest
        r'\/([^\/]+)\/.*\.m4s',  # DASH segments
        r'\/([^\/]+)\/.*\.mp4'  # MP4 segments
    ]

    for pattern in patterns:
        match = re.search(pattern, path)
        if match:
            return match.group(1)
    
    # Also check for channel name in path with common streaming patterns
    path_parts = path.split('/')
    if len(path_parts) > 1:
        # Look for potential channel name (between slashes)
        for part in path_parts:
            if part and not part.endswith(('.m3u8', '.ts', '.mpd', '.m4s', '.mp4')):
                # Check if it might be a channel name (alphanumeric and common separators)
                if re.match(r'^[a-zA-Z0-9_-]+$', part):
                    return part
    
    return None

def get_geoip_city_info(ip):
    """Get GeoIP city information for an IP address"""
    try:
        response = city_reader.city(ip)
        return (
            response.country.name or "Unknown",
            response.city.name or "Unknown",
            response.location.latitude or 0,
            response.location.longitude or 0
        )
    except geoip2.errors.AddressNotFoundError:
        return "Unknown", "Unknown", 0, 0
    except Exception as e:
        print(f"GeoIP City error for {ip}: {e}")
        return "Unknown", "Unknown", 0, 0

def get_geoip_asn_info(ip):
    """Get GeoIP ASN information for an IP address"""
    try:
        response = asn_reader.asn(ip)
        return (
            response.autonomous_system_number or 0,
            response.autonomous_system_organization or "Unknown"
        )
    except geoip2.errors.AddressNotFoundError:
        return 0, "Unknown"
    except Exception as e:
        print(f"GeoIP ASN error for {ip}: {e}")
        return 0, "Unknown"

def write_metrics(metrics, current_time):
    """Write all metrics to the metrics file"""
    try:
        with open(METRICS_FILE, 'w') as f:
            # IP request counts
            f.write('# HELP nginx_ip_request_count Total requests per IP\n')
            f.write('# TYPE nginx_ip_request_count counter\n')
            for ip, count in metrics['ip_requests'].items():
                f.write(f'nginx_ip_request_count{{ip="{ip}"}} {count}\n')

            # IP bandwidth with City and ASN info
            f.write('\n# HELP nginx_ip_bandwidth Bandwidth per IP (Mbps)\n')
            f.write('# TYPE nginx_ip_bandwidth gauge\n')
            active_ips = {ip: data for ip, data in metrics['ip_bandwidth'].items()
                         if ip in ip_activity and
                         (current_time - ip_activity[ip]['last_seen']) <= INACTIVITY_TIMEOUT}

            for ip, data in active_ips.items():
                country, city, lat, lon = get_geoip_city_info(ip)
                asn_number, asn_org = get_geoip_asn_info(ip)
                bandwidth_mbps = (data['bytes'] / UPDATE_INTERVAL) * BYTES_TO_MBITS
                f.write(
                    f'nginx_ip_bandwidth{{ip="{ip}",country="{country}",'
                    f'city="{city}",latitude="{lat}",longitude="{lon}",'
                    f'asn="{asn_number}",asn_org="{asn_org}"}} '
                    f'{bandwidth_mbps}\n'
                )

            # Channel traffic
            f.write('\n# HELP nginx_channel_traffic IPs per channel\n')
            f.write('# TYPE nginx_channel_traffic gauge\n')
            for channel, ips in metrics['channel_access'].items():
                f.write(f'nginx_channel_traffic{{channel="{channel}"}} {len(ips)}\n')
                for ip in ips:
                    country, city, lat, lon = get_geoip_city_info(ip)
                    asn_number, asn_org = get_geoip_asn_info(ip)
                    f.write(
                        f'nginx_channel_ip_access{{channel="{channel}",ip="{ip}",'
                        f'country="{country}",city="{city}",latitude="{lat}",'
                        f'longitude="{lon}",asn="{asn_number}",asn_org="{asn_org}"}} 1\n'
                    )

            # Summary metrics
            f.write('\n# HELP nginx_total_active_ips Total active IPs\n')
            f.write('# TYPE nginx_total_active_ips gauge\n')
            f.write(f'nginx_total_active_ips {len(active_ips)}\n')

            f.write('\n# HELP nginx_total_active_channels Total active channels\n')
            f.write('# TYPE nginx_total_active_channels gauge\n')
            f.write(f'nginx_total_active_channels {len(metrics["channel_access"])}\n')

            # ASN-based bandwidth aggregation
            f.write('\n# HELP nginx_asn_bandwidth Bandwidth per ASN (Mbps)\n')
            f.write('# TYPE nginx_asn_bandwidth gauge\n')
            asn_bandwidth = defaultdict(float)
            for ip, data in active_ips.items():
                asn_number, asn_org = get_geoip_asn_info(ip)
                bandwidth_mbps = (data['bytes'] / UPDATE_INTERVAL) * BYTES_TO_MBITS
                asn_bandwidth[(asn_number, asn_org)] += bandwidth_mbps
            
            for (asn_number, asn_org), bandwidth in asn_bandwidth.items():
                f.write(
                    f'nginx_asn_bandwidth{{asn="{asn_number}",asn_org="{asn_org}"}} '
                    f'{bandwidth}\n'
                )

    except Exception as e:
        print(f"Error writing metrics: {e}")

def monitor_nginx_traffic():
    """Main monitoring function"""
    print(f"Monitoring Nginx traffic from {LOG_FILE}...")
    print(f"Using GeoIP City DB: {GEOIP_CITY_DB_PATH}")
    print(f"Using GeoIP ASN DB: {GEOIP_ASN_DB_PATH}")
    print(f"Metrics will be written to: {METRICS_FILE}")

    metrics = {
        'ip_requests': defaultdict(int),
        'ip_bandwidth': defaultdict(lambda: {'bytes': 0}),
        'channel_traffic': defaultdict(int),
        'channel_access': defaultdict(set)
    }

    last_update = time.time()
    last_cleanup = time.time()

    try:
        for log_entry in tail_log_file():
            ip, path, bytes_transferred, method = parse_log_entry(log_entry)
            current_time = time.time()

            if ip:
                # Update IP activity
                if not ip_activity[ip]['active']:
                    ip_activity[ip]['active'] = True
                    ip_activity[ip]['bandwidth'] = 0
                    # Initialize with 0 bandwidth
                    metrics['ip_bandwidth'][ip]['bytes'] = 0

                # Update metrics
                metrics['ip_requests'][ip] += 1
                metrics['ip_bandwidth'][ip]['bytes'] += bytes_transferred
                ip_activity[ip]['last_seen'] = current_time
                ip_activity[ip]['bandwidth'] += bytes_transferred

                # Extract channel name if applicable (now supports .mpd)
                channel_name = extract_channel_name(path)
                if channel_name:
                    metrics['channel_access'][channel_name].add(ip)
                    if path.endswith('.mpd'):
                        print(f"DASH stream detected: Channel {channel_name} from IP {ip}")

            # Periodic update
            if current_time - last_update >= UPDATE_INTERVAL:
                # Check for inactive IPs
                for ip in list(ip_activity.keys()):
                    if current_time - ip_activity[ip]['last_seen'] > UPDATE_INTERVAL:
                        if ip_activity[ip]['active']:
                            metrics['ip_bandwidth'][ip]['bytes'] = 0
                            ip_activity[ip]['active'] = False

                # Clean up inactive IPs every 10 minutes
                if current_time - last_cleanup >= INACTIVITY_TIMEOUT:
                    inactive_ips = [ip for ip, data in ip_activity.items()
                                  if current_time - data['last_seen'] >= INACTIVITY_TIMEOUT]
                    for ip in inactive_ips:
                        del ip_activity[ip]
                    last_cleanup = current_time

                # Write metrics
                write_metrics(metrics, current_time)

                # Reset metrics
                metrics['ip_requests'].clear()
                for ip in metrics['ip_bandwidth']:
                    metrics['ip_bandwidth'][ip]['bytes'] = 0
                metrics['channel_access'].clear()

                last_update = current_time

    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
    except Exception as e:
        print(f"Monitoring error: {e}")
    finally:
        city_reader.close()
        asn_reader.close()

if __name__ == "__main__":
    monitor_nginx_traffic()
