import subprocess
import netifaces
import re
import platform

# Common constants moved outside functions
RISKY_PORTS = {'21/tcp', '23/tcp', '445/tcp', '139/tcp'}
KNOWN_VULNERABILITIES = {
    'ftp': ['vsftpd 2.3.4'],
    'ssh': ['OpenSSH 7.2', 'OpenSSH 7.3'],
    'smb': ['Samba 3.0.20', 'Samba 3.0.25'],
}

# Regex patterns precompiled for performance
PORT_PATTERN = re.compile(r'^(\d+/tcp)\s+open\s+([^\s]+)')
NMAP_SCAN_PATTERN = re.compile(r'Nmap scan report for (\S+)')

# Automatically detect local IP range in CIDR format
def get_ip_range():
    interfaces = netifaces.interfaces()
    for iface in interfaces:
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                ip = addr['addr']
                netmask = addr['netmask']
                if ip != "127.0.0.1":
                    cidr = sum(bin(int(x)).count('1') for x in netmask.split('.'))
                    base_ip = '.'.join(ip.split('.')[:3]) + '.0'
                    return f"{base_ip}/{cidr}"
    return None

# Discover active devices on the network
def discover_devices(network_range):
    try:
        result = subprocess.check_output(['nmap', '-sn', network_range], text=True)
    except subprocess.CalledProcessError:
        return []

    active_ips = []
    for line in result.splitlines():
        match = NMAP_SCAN_PATTERN.search(line)
        if match:
            active_ips.append(match.group(1))
    return active_ips

# Scan open ports and services
def scan_ports_services(ip):
    try:
        result = subprocess.check_output(['nmap', '-sV', ip], text=True)
        return result
    except subprocess.CalledProcessError as e:
        return f"Scan failed for {ip}: {str(e)}"
    except Exception as e:
        return f"Scan failed for {ip}: {str(e)}"

# Ping a device to measure latency
def ping_device(ip):
    system = platform.system()

    if system == "Windows":
        command = ["ping", "-n", "1", ip]
        pattern = r"Average = (\d+)ms"
    else:
        command = ["ping", "-c", "1", ip]
        pattern = r"time=(\d+\.\d+) ms"

    try:
        output = subprocess.check_output(command, text=True)
        match = re.search(pattern, output)
        if match:
            return float(match.group(1))
    except subprocess.CalledProcessError:
        return None

    return None

# Extract open ports from nmap output
def parse_open_ports(scan_output):
    if not isinstance(scan_output, str):
        return []  # Fix: gracefully handle non-string input
    ports = []
    for line in scan_output.splitlines():
        match = PORT_PATTERN.match(line)
        if match:
            ports.append(match.group(1))
    return ports

# Check for risky ports and known vulnerable services
def detect_vulnerabilities(scan_output):
    if not isinstance(scan_output, str):
        return False  # Fix: gracefully handle non-string input
    open_ports = parse_open_ports(scan_output)
    for port in open_ports:
        if port in RISKY_PORTS:
            return True

    for line in scan_output.splitlines():
        for service, versions in KNOWN_VULNERABILITIES.items():
            for version in versions:
                if service in line and version in line:
                    return True

    return False

# Detailed OS and MAC vendor scan
def scan_host(ip):
    try:
        result = subprocess.run(
            ['sudo', 'nmap', '-O', '-sV', '-Pn', ip],
            capture_output=True,
            text=True,
            timeout=180
        )
        output = result.stdout
        lines = output.splitlines()

        def extract_field(patterns):
            for line in lines:
                for pattern in patterns:
                    if pattern in line:
                        return line.split(":", 1)[-1].strip()
            return "Unknown"

        def extract_mac_vendor():
            for line in lines:
                if "MAC Address:" in line:
                    parts = line.split("MAC Address:")[1].split(" ", 1)
                    if len(parts) > 1:
                        return parts[1].strip("()")
            return "Unknown"

        def extract_services():
            services = []
            capture = False
            for line in lines:
                if line.startswith("PORT"):
                    capture = True
                    continue
                if capture and line.strip() == "":
                    break
                if capture:
                    services.append(line.strip())
            return services

        device_info = {
            "ip": ip,
            "device_type": extract_field(["Device type:"]),
            "os": extract_field(["Running:", "OS details:"]),
            "mac_vendor": extract_mac_vendor(),
            # "services": extract_services(),           # ← New: service lines
            # "full_scan_output": output.strip()        # ← New: entire output
        }

        return device_info

    except subprocess.TimeoutExpired:
        return {
            "ip": ip,
            "device_type": "Timeout",
            "os": "Timeout",
            "mac_vendor": "Timeout",
            "services": [],
            # "full_scan_output": "Scan timed out"
        }
    except Exception as e:
        return {
            "ip": ip,
            "device_type": "Unknown",
            "os": "Unknown",
            "mac_vendor": "Unknown",
            "error": str(e),
            "services": [],
            # "full_scan_output": f"Error: {str(e)}"
        }
