import subprocess
import socket
from flask import Flask, render_template, jsonify, request, redirect, url_for
from scapy.all import ARP, Ether, srp
import re
import time
import platform
import nmap
import requests

app = Flask(__name__)

# Function to resolve the hostname of a given IP address
def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown Device"

# Function to get the router's IP address based on the OS
def get_router_ip():
    try:
        system_platform = platform.system().lower()
        if system_platform == "windows":
            result = subprocess.run(['ipconfig'], stdout=subprocess.PIPE, text=True)
            for line in result.stdout.split('\n'):
                if "Default Gateway" in line:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        return match.group(1)
        elif system_platform in ["linux", "darwin"]:
            result = subprocess.run(['ip', 'route'], stdout=subprocess.PIPE, text=True)
            for line in result.stdout.split('\n'):
                if "default via" in line:
                    parts = line.split()
                    return parts[2]
    except Exception as e:
        print(f"Error getting router IP: {e}")
    return None

# Function to scan the network
def scan_network():
    devices = []
    try:
        gateway_ip = get_router_ip()
        if gateway_ip is None:
            return []
        ip_range = f"{gateway_ip}/24"
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=2, verbose=0)[0]
        for sent, received in result:
            hostname = resolve_hostname(received.psrc)
            devices.append({"ip": received.psrc, "mac": received.hwsrc, "name": hostname})
        return devices
    except Exception as e:
        print(f"Error scanning network: {e}")
    return []

# Function to scan open ports
def scan_ports(router_ip):
    try:
        scanner = nmap.PortScanner()
        start_time = time.time()
        scanner.scan(hosts=router_ip, arguments='-p 1-1024')
        elapsed_time = time.time() - start_time
        open_ports = [
            port for port in scanner[router_ip]['tcp']
            if scanner[router_ip]['tcp'][port]['state'] == 'open'
        ]
        return open_ports, f"{elapsed_time:.2f} seconds"
    except Exception as e:
        return str(e), None

# Function to check password strength
def check_password_strength(password, router_ip):
    criteria = {
        "length": len(password) >= 8,
        "uppercase": bool(re.search(r'[A-Z]', password)),
        "lowercase": bool(re.search(r'[a-z]', password)),
        "digit": bool(re.search(r'\d', password)),
        "special": bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    }
    suggestions = [
        "Use at least 8 characters.",
        "Include at least one uppercase letter.",
        "Include at least one lowercase letter.",
        "Include at least one digit.",
        "Include at least one special character."
    ]
    if all(criteria.values()):
        return "Strong", [], None
    else:
        return "Weak", [s for c, s in zip(criteria.values(), suggestions) if not c], {
            "steps": [
                "1. Go to your router's admin panel.",
                "2. Enter admin credentials.",
                "3. Locate 'Change Password' in settings.",
                "4. Update to a strong password.",
                "5. Save changes and restart the router."
            ],
            "admin_panel_url": f"http://{router_ip}"
        }

# Route for scanning open ports
@app.route('/scan_ports', methods=['POST'])
def scan_ports_route():
    router_ip = request.json.get('router_ip', get_router_ip())
    open_ports, elapsed_time = scan_ports(router_ip)
    return jsonify({'open_ports': open_ports, 'time_taken': elapsed_time})

# Route for checking password strength
@app.route('/check_password', methods=['POST'])
def check_password_route():
    password = request.json.get('password')
    router_ip = get_router_ip()
    strength, suggestions, guide = check_password_strength(password, router_ip)
    return jsonify({'strength': strength, 'suggestions': suggestions, 'guide': guide})

# Route for firmware check
@app.route('/firmware_check', methods=['POST'])
def firmware_check():
    router_ip = get_router_ip()
    firmware_url = f"http://{router_ip}/firmware"
    return jsonify({
        'status': 'success',
        'message': f"Visit {firmware_url} to check and update your firmware."
    })

# New route for getting the default gateway
@app.route('/get_default_gateway', methods=['GET'])
def get_default_gateway():
    router_ip = get_router_ip()
    return jsonify({"default_gateway": router_ip})

@app.route('/')
def home():
    router_ip = get_router_ip()
    return render_template('index.html', router_ip=router_ip)

@app.route('/scan', methods=['POST'])
def scan():
    devices = scan_network()
    return jsonify(devices)

@app.route('/block_device', methods=['POST'])
def block_device_route():
    ip_or_mac = request.json.get('ip_or_mac')
    router_ip = get_router_ip()
    
    if not ip_or_mac:
        return jsonify({'error': 'IP or MAC address is required.'}), 400

    result = block_device(ip_or_mac, router_ip)
    return jsonify({'status': result})

if __name__ == '__main__':
    app.run(debug=True)
