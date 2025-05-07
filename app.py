from flask import Flask, render_template
from flask_socketio import SocketIO, emit
import scanner  # Import your scanner.py functions
import time

app = Flask(__name__)
socketio = SocketIO(app)

@app.route('/')
def index():
    return render_template('index.html')

# Listen for start_scan event from the client
@socketio.on('start_scan')
def handle_start_scan():
    print("Received start_scan event")  # Debug log
    socketio.emit('scan_start', {'message': 'Starting network scan...'})
    
    # Get local IP range
    network_range = scanner.get_ip_range()
    print(f"Network Range: {network_range}")

    if not network_range:
        socketio.emit('scan_error', {'message': "Could not detect local IP range"})
        return

    # Emit the detected IP range
    socketio.emit('scan_ip_range', {'ip_range': network_range})

    # Discover active devices on the network
    active_devices = scanner.discover_devices(network_range)
    if not active_devices:
        socketio.emit('scan_error', {'message': "No active devices found"})
        return
    print(f"Active Devices: {active_devices}")
    # Emit the active devices
    socketio.emit('scan_active_devices', {'devices': active_devices})

    for idx, device in enumerate(active_devices):
        latency = scanner.ping_device(device)
        scan_output = scanner.scan_ports_services(device)

        # Parse useful info from scan_output
        open_ports = scanner.parse_open_ports(scan_output)
        vulnerable = scanner.detect_vulnerabilities(open_ports)
        
        device_info = scanner.scan_host(device)

        result_summary = {
            'latency_ms': latency,
            'open_ports': open_ports,
            'vulnerable': vulnerable,
            'device_type': device_info.get('device_type', 'Unknown'),
            'os': device_info.get('os', 'Unknown'),
            'mac_vendor': device_info.get('mac_vendor', 'Unknown'),
            # 'services': device_info.get('services', 'Unknown'), 
        }
        
        print(result_summary)

        socketio.emit('scan_result', {'ip': device, 'result': result_summary})
        # Emit progress
        progress = int(((idx + 1) / len(active_devices)) * 100)
        socketio.emit('scan_progress', {'percent': progress})

    # Emit the final scan results
    socketio.emit('scan_complete', {'message': 'Scan complete.'})

# Set up SocketIO event listeners (these will be triggered on the client side)
@socketio.on('connect')
def handle_connect():
    print("Client connected")

@socketio.on('disconnect')
def handle_disconnect():
    print("Client disconnected")

if __name__ == '__main__':
    socketio.run(app, debug=True)

