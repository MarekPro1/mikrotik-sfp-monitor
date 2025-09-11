#!/usr/bin/env python3
"""
MikroTik SFP Port Statistics Collector
Connects to all MikroTik routers on the network and retrieves Rx stats from SFP ports
"""

import sys
import json
import argparse
import ipaddress
import struct
import time
import os
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple
import socket

# Platform-specific imports
if os.name == 'nt':
    import msvcrt
else:
    msvcrt = None

try:
    import paramiko
except ImportError:
    print("Error: paramiko library is required. Install it with: pip install paramiko")
    sys.exit(1)

try:
    from librouteros import connect
    from librouteros.exceptions import TrapError, FatalError
except ImportError:
    print("Error: librouteros library is required. Install it with: pip install librouteros")
    sys.exit(1)

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)  # Initialize colorama for Windows
    COLORS_AVAILABLE = True
except ImportError:
    # Fallback if colorama not installed
    COLORS_AVAILABLE = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Back:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ''


class MikroTikSFPCollector:
    """Collects SFP statistics from MikroTik routers"""
    
    def __init__(self, username: str, password: str, port: int = 8728, ssh_port: int = 22, use_ssh: bool = False):
        self.username = username
        self.password = password
        self.port = port
        self.ssh_port = ssh_port
        self.use_ssh = use_ssh
        self.results = []
        self.baseline_stats = {}  # Store baseline values for software reset
        self.reset_time = None  # Track when reset was pressed
        self.error_history = {}  # Track error history for rate calculation
        self.last_clear_time = 0  # Track last screen clear to reduce blinking
        self.previous_stats = {}  # Store previous stats for rate calculation
        self.last_collection_time = {}  # Store last collection time for each port
        self.link_state_history = {}  # Track link up/down events
        self.packet_size_dist = {}  # Store packet size distribution
        self.pause_frames = {}  # Track pause frame counts
        self.queue_drops = {}  # Track queue drop rates
    
    def load_hosts_from_file(self, filename: str = "mikrotik_hosts.txt") -> List[str]:
        """Load host IPs from configuration file"""
        hosts = []
        if os.path.exists(filename):
            try:
                with open(filename, 'r') as f:
                    for line in f:
                        line = line.strip()
                        # Skip comments and empty lines
                        if line and not line.startswith('#'):
                            # Validate IP address
                            try:
                                ipaddress.ip_address(line)
                                hosts.append(line)
                                print(f"  Loaded host from config: {line}")
                            except ValueError:
                                print(f"  Warning: Invalid IP address in config: {line}")
            except Exception as e:
                print(f"  Error reading config file: {e}")
        return hosts
    
    def discover_mikrotik_devices(self, timeout: float = 15.0) -> List[Dict]:
        """Discover MikroTik devices using MNDP (MikroTik Neighbor Discovery Protocol)"""
        print("Discovering MikroTik devices using MNDP protocol...")
        devices = []
        
        # MNDP uses UDP port 5678
        MNDP_PORT = 5678
        MNDP_MULTICAST = '255.255.255.255'
        
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(2.0)  # Increased timeout
            
            # Try to bind to MNDP port
            try:
                sock.bind(('', MNDP_PORT))
            except OSError:
                # Port might be in use, try another port
                sock.bind(('', 0))
                print("  Note: Could not bind to MNDP port 5678, using alternative port")
            
            # Send multiple discovery packets to ensure all devices respond
            # Send in bursts for better coverage
            for burst in range(3):  # 3 bursts
                for i in range(5):  # 5 packets per burst
                    discovery_packet = b'\x00\x00\x00\x00'
                    sock.sendto(discovery_packet, (MNDP_MULTICAST, MNDP_PORT))
                    time.sleep(0.05)  # Very fast within burst
                time.sleep(0.3)  # Pause between bursts
            
            # Collect responses
            start_time = time.time()
            seen_devices = set()
            
            while time.time() - start_time < timeout:
                try:
                    data, addr = sock.recvfrom(1500)
                    if addr[0] not in seen_devices and len(data) > 20:
                        # Basic MNDP packet parsing
                        device_info = self._parse_mndp_packet(data, addr[0])
                        if device_info:
                            devices.append(device_info)
                            seen_devices.add(addr[0])
                            # Don't print during continuous discovery
                except socket.timeout:
                    continue
                except Exception as e:
                    continue
            
            sock.close()
            
        except Exception as e:
            print(f"MNDP discovery warning: {e}")
        
        return devices
    
    def _parse_mndp_packet(self, data: bytes, ip: str) -> Optional[Dict]:
        """Parse MNDP packet to extract device information"""
        try:
            # MNDP packets contain TLV (Type-Length-Value) fields
            device = {'ip': ip, 'identity': 'Unknown', 'version': '', 'platform': ''}
            
            offset = 0
            while offset < len(data) - 4:
                if offset + 4 > len(data):
                    break
                    
                # Read TLV header
                tlv_type = struct.unpack('>H', data[offset:offset+2])[0]
                tlv_length = struct.unpack('>H', data[offset+2:offset+4])[0]
                
                if offset + 4 + tlv_length > len(data):
                    break
                
                tlv_value = data[offset+4:offset+4+tlv_length]
                
                # Parse known TLV types
                if tlv_type == 0x0001:  # MAC address
                    if len(tlv_value) == 6:
                        device['mac'] = ':'.join(f'{b:02x}' for b in tlv_value)
                elif tlv_type == 0x0005:  # Identity
                    device['identity'] = tlv_value.decode('utf-8', errors='ignore').strip('\x00')
                elif tlv_type == 0x0007:  # Version
                    device['version'] = tlv_value.decode('utf-8', errors='ignore').strip('\x00')
                elif tlv_type == 0x0008:  # Platform
                    device['platform'] = tlv_value.decode('utf-8', errors='ignore').strip('\x00')
                elif tlv_type == 0x000a:  # Uptime
                    if len(tlv_value) == 4:
                        device['uptime'] = struct.unpack('>I', tlv_value)[0]
                elif tlv_type == 0x000b:  # Software ID
                    device['software_id'] = tlv_value.decode('utf-8', errors='ignore').strip('\x00')
                elif tlv_type == 0x000c:  # Board
                    device['board'] = tlv_value.decode('utf-8', errors='ignore').strip('\x00')
                elif tlv_type == 0x0010:  # IPv6 address
                    if len(tlv_value) == 16:
                        device['ipv6'] = ':'.join(f'{struct.unpack(">H", tlv_value[i:i+2])[0]:04x}' 
                                                 for i in range(0, 16, 2))
                
                offset += 4 + tlv_length
            
            return device if device['identity'] != 'Unknown' else None
            
        except Exception as e:
            return None
    
    
    def get_sfp_stats_api(self, host: str) -> Dict:
        """Get SFP statistics using RouterOS API"""
        stats = {
            'host': host,
            'hostname': 'Unknown',
            'sfp_ports': [],
            'ethernet_ports': [],  # Add ethernet ports collection
            'error': None
        }
        
        try:
            # Connect to RouterOS API
            api = connect(
                username=self.username,
                password=self.password,
                host=host,
                port=self.port
            )
            
            # Get system identity
            identity = list(api('/system/identity/print'))
            if identity:
                stats['hostname'] = identity[0].get('name', 'Unknown')
            
            # Get system resource info (includes version)
            try:
                resource = list(api('/system/resource/print'))
                if resource:
                    res = resource[0]
                    stats['version'] = res.get('version', 'Unknown')
                    stats['board_name'] = res.get('board-name', 'Unknown')
                    stats['architecture'] = res.get('architecture-name', 'Unknown')
                    stats['uptime'] = res.get('uptime', 'Unknown')
                    stats['cpu_load'] = res.get('cpu-load', 0)
                    # Add memory statistics
                    stats['total_memory'] = res.get('total-memory', 0)
                    stats['free_memory'] = res.get('free-memory', 0)
                    if stats['total_memory'] > 0:
                        stats['memory_usage_percent'] = int(((stats['total_memory'] - stats['free_memory']) / stats['total_memory']) * 100)
                    else:
                        stats['memory_usage_percent'] = 0
            except:
                pass
            
            # Get RouterBOARD info
            try:
                routerboard = list(api('/system/routerboard/print'))
                if routerboard:
                    rb = routerboard[0]
                    stats['routerboard_version'] = rb.get('current-firmware', 'Unknown')
                    stats['routerboard_model'] = rb.get('model', 'Unknown')
                    stats['serial_number'] = rb.get('serial-number', 'Unknown')
            except:
                pass
            
            # Get interface list
            interfaces = list(api('/interface/print'))
            
            # Get ethernet monitor stats for ALL ethernet interfaces
            for interface in interfaces:
                if_name = interface.get('name', '')
                if_type = interface.get('type', '')
                
                # Check all ethernet interfaces and SFP+ interfaces
                # Also check for sfp-sfpplus type
                if if_type in ['ether', 'sfp-sfpplus'] or 'sfp' in if_name.lower():
                    try:
                        # Get monitor stats  
                        monitor_data = list(api('/interface/ethernet/monitor', 
                                         **{'numbers': if_name, 'once': True}))
                        
                        if monitor_data:
                            mon = monitor_data[0]
                            
                            # Check for any SFP-related fields to detect SFP presence
                            has_sfp = False
                            sfp_fields = ['sfp-module-present', 'sfp-vendor-name', 'sfp-rx-power', 
                                        'sfp-tx-power', 'sfp-temperature', 'sfp-supply-voltage']
                            
                            for field in sfp_fields:
                                value = mon.get(field)
                                if value and value != 'N/A':
                                    has_sfp = True
                                    break
                            
                            # Also check sfp-module-present specifically
                            sfp_present = mon.get('sfp-module-present', False)
                            if sfp_present == 'true' or sfp_present == True or sfp_present == 'yes':
                                has_sfp = True
                            
                            if has_sfp:
                                sfp_info = {
                                    'interface': if_name,
                                    'status': mon.get('status', 'unknown'),
                                    'sfp_vendor': mon.get('sfp-vendor-name', 'N/A'),
                                    'sfp_part_number': mon.get('sfp-vendor-part-number', 'N/A'),
                                    'sfp_wavelength': mon.get('sfp-wavelength', 'N/A'),
                                    'sfp_temperature': mon.get('sfp-temperature', 'N/A'),
                                    'sfp_rx_power': mon.get('sfp-rx-power', 'N/A'),
                                    'sfp_tx_power': mon.get('sfp-tx-power', 'N/A'),
                                    'rate': mon.get('rate', 'N/A'),
                                    'full_duplex': mon.get('full-duplex', 'false') == 'true'
                                }
                                
                                # Get comprehensive interface statistics
                                stats_query = api('/interface/print')
                                stats_list = list(stats_query)
                                
                                # Get ethernet stats for more detailed error information
                                eth_stats = list(api('/interface/ethernet/print'))
                                
                                # Get system resource info for enhanced monitoring
                                queue_stats = []
                                try:
                                    # Try to get queue statistics
                                    queue_query = api('/queue/simple/print')
                                    queue_stats = list(queue_query)
                                except:
                                    pass
                                
                                # Find statistics for this specific interface
                                for st in stats_list:
                                    if st.get('name') == if_name:
                                        sfp_info.update({
                                            'rx_bytes': int(st.get('rx-byte', 0)),
                                            'rx_packets': int(st.get('rx-packet', 0)),
                                            'tx_bytes': int(st.get('tx-byte', 0)),
                                            'tx_packets': int(st.get('tx-packet', 0)),
                                            'rx_errors': int(st.get('rx-error', 0)),
                                            'tx_errors': int(st.get('tx-error', 0)),
                                            'rx_drops': int(st.get('rx-drop', 0)),
                                            'tx_drops': int(st.get('tx-drop', 0))
                                        })
                                        break
                                
                                # Get detailed ethernet error statistics
                                for eth in eth_stats:
                                    if eth.get('name') == if_name:
                                        sfp_info.update({
                                            'rx_fcs_error': int(eth.get('rx-fcs-error', 0)),
                                            'rx_align_error': int(eth.get('rx-align-error', 0)),
                                            'rx_fragment': int(eth.get('rx-fragment', 0)),
                                            'rx_overflow': int(eth.get('rx-overflow', 0)),
                                            'rx_too_long': int(eth.get('rx-too-long', 0)),
                                            'rx_too_short': int(eth.get('rx-too-short', 0)),
                                            'rx_64': int(eth.get('rx-64', 0)),
                                            'rx_65_127': int(eth.get('rx-65-127', 0)),
                                            'rx_128_255': int(eth.get('rx-128-255', 0)),
                                            'rx_256_511': int(eth.get('rx-256-511', 0)),
                                            'rx_512_1023': int(eth.get('rx-512-1023', 0)),
                                            'rx_1024_1518': int(eth.get('rx-1024-1518', 0)),
                                            'rx_1519_max': int(eth.get('rx-1519-max', 0)),
                                            'rx_pause': int(eth.get('rx-pause', 0)),
                                            'tx_collision': int(eth.get('tx-collision', 0)),
                                            'tx_excessive_collision': int(eth.get('tx-excessive-collision', 0)),
                                            'tx_late_collision': int(eth.get('tx-late-collision', 0)),
                                            'tx_pause': int(eth.get('tx-pause', 0)),
                                            'tx_queue_drop': int(eth.get('tx-queue-drop', 0)),
                                            'link_downs': int(eth.get('link-downs', 0))
                                        })
                                        
                                        # Store packet size distribution
                                        key = f"{host}_{if_name}"
                                        self.packet_size_dist[key] = {
                                            '64': sfp_info.get('rx_64', 0),
                                            '65-127': sfp_info.get('rx_65_127', 0),
                                            '128-255': sfp_info.get('rx_128_255', 0),
                                            '256-511': sfp_info.get('rx_256_511', 0),
                                            '512-1023': sfp_info.get('rx_512_1023', 0),
                                            '1024-1518': sfp_info.get('rx_1024_1518', 0),
                                            '1519+': sfp_info.get('rx_1519_max', 0)
                                        }
                                        
                                        # Store pause frame info
                                        self.pause_frames[key] = {
                                            'rx': sfp_info.get('rx_pause', 0),
                                            'tx': sfp_info.get('tx_pause', 0)
                                        }
                                        
                                        # Track link state changes
                                        if key not in self.link_state_history:
                                            self.link_state_history[key] = {
                                                'link_downs': sfp_info.get('link_downs', 0),
                                                'last_state': sfp_info.get('status', 'unknown'),
                                                'flap_count': 0,
                                                'last_change': time.time()
                                            }
                                        else:
                                            current_downs = sfp_info.get('link_downs', 0)
                                            if current_downs > self.link_state_history[key]['link_downs']:
                                                self.link_state_history[key]['flap_count'] += 1
                                                self.link_state_history[key]['link_downs'] = current_downs
                                                self.link_state_history[key]['last_change'] = time.time()
                                        
                                        break
                                
                                # Track queue drops if available
                                for q in queue_stats:
                                    if q.get('target') and if_name in q.get('target', ''):
                                        key = f"{host}_{if_name}"
                                        self.queue_drops[key] = {
                                            'drops': int(q.get('drops', 0)),
                                            'queued': int(q.get('queued-packets', 0))
                                        }
                                        break
                                
                                stats['sfp_ports'].append(sfp_info)
                    except (TrapError, FatalError) as e:
                        # Interface might not support monitoring
                        continue
            
            api.close()
            
        except Exception as e:
            stats['error'] = str(e)
            print(f"  Error connecting to {host}: {e}")
        
        return stats
    
    def get_sfp_stats_ssh(self, host: str) -> Dict:
        """Get SFP statistics using SSH"""
        stats = {
            'host': host,
            'hostname': 'Unknown',
            'sfp_ports': [],
            'error': None
        }
        
        try:
            # SSH connection
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, port=self.ssh_port, username=self.username, password=self.password)
            
            # Get system identity
            stdin, stdout, stderr = ssh.exec_command('/system identity print')
            output = stdout.read().decode('utf-8')
            if 'name:' in output:
                stats['hostname'] = output.split('name:')[1].strip().split('\n')[0]
            
            # Get SFP interfaces
            stdin, stdout, stderr = ssh.exec_command('/interface ethernet monitor numbers=[find] once')
            output = stdout.read().decode('utf-8')
            
            # Parse output for SFP information
            current_interface = None
            sfp_data = {}
            
            for line in output.split('\n'):
                line = line.strip()
                if line.startswith('name:'):
                    if current_interface and 'sfp-module-present: yes' in str(sfp_data):
                        # Save previous interface if it has SFP
                        sfp_info = self._parse_sfp_data(current_interface, sfp_data)
                        if sfp_info:
                            stats['sfp_ports'].append(sfp_info)
                    current_interface = line.split('name:')[1].strip()
                    sfp_data = {}
                elif ':' in line:
                    key, value = line.split(':', 1)
                    sfp_data[key.strip()] = value.strip()
            
            # Don't forget the last interface
            if current_interface and 'sfp-module-present: yes' in str(sfp_data):
                sfp_info = self._parse_sfp_data(current_interface, sfp_data)
                if sfp_info:
                    stats['sfp_ports'].append(sfp_info)
            
            ssh.close()
            
        except Exception as e:
            stats['error'] = str(e)
            print(f"  Error connecting to {host} via SSH: {e}")
        
        return stats
    
    def _parse_sfp_data(self, interface: str, data: Dict) -> Optional[Dict]:
        """Parse SFP data from raw output"""
        sfp_info = {
            'interface': interface,
            'status': data.get('status', 'unknown'),
            'sfp_vendor': data.get('sfp-vendor-name', 'N/A'),
            'sfp_part_number': data.get('sfp-vendor-part-number', 'N/A'),
            'sfp_wavelength': data.get('sfp-wavelength', 'N/A'),
            'sfp_temperature': data.get('sfp-temperature', 'N/A'),
            'sfp_rx_power': data.get('sfp-rx-power', 'N/A'),
            'sfp_tx_power': data.get('sfp-tx-power', 'N/A'),
            'rate': data.get('rate', 'N/A'),
            'full_duplex': data.get('full-duplex', 'no') == 'yes'
        }
        return sfp_info
    
    def collect_from_hosts(self, hosts: List[str], max_workers: int = 5, quiet: bool = False) -> List[Dict]:
        """Collect SFP statistics from multiple hosts concurrently"""
        if not quiet:
            print(f"\nCollecting SFP statistics from {len(hosts)} hosts...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            if self.use_ssh:
                futures = {executor.submit(self.get_sfp_stats_ssh, host): host for host in hosts}
            else:
                futures = {executor.submit(self.get_sfp_stats_api, host): host for host in hosts}
            
            for future in as_completed(futures):
                host = futures[future]
                try:
                    result = future.result()
                    self.results.append(result)
                    if not quiet and not result['error']:
                        print(f"  Collected from {host} ({result['hostname']}): {len(result['sfp_ports'])} SFP ports")
                except Exception as e:
                    if not quiet:
                        print(f"  Failed to collect from {host}: {e}")
                    self.results.append({
                        'host': host,
                        'hostname': 'Unknown',
                        'sfp_ports': [],
                        'error': str(e)
                    })
        
        return self.results
    
    def reset_interface_counters(self, hosts: List[str]):
        """Software-based counter reset using baseline tracking"""
        print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{Style.BRIGHT}RESETTING COUNTERS (Software Mode){Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
        
        # Store current values as baseline
        self.baseline_stats = {}
        self.reset_time = datetime.now()
        
        for device in self.results:
            if device['error']:
                continue
                
            device_key = device['host']
            self.baseline_stats[device_key] = {}
            
            for sfp in device['sfp_ports']:
                port_key = sfp['interface']
                # Store all counter values as baseline
                self.baseline_stats[device_key][port_key] = {
                    'rx_bytes': sfp.get('rx_bytes', 0),
                    'tx_bytes': sfp.get('tx_bytes', 0),
                    'rx_packets': sfp.get('rx_packets', 0),
                    'tx_packets': sfp.get('tx_packets', 0),
                    'rx_errors': sfp.get('rx_errors', 0),
                    'tx_errors': sfp.get('tx_errors', 0),
                    'rx_drops': sfp.get('rx_drops', 0),
                    'tx_drops': sfp.get('tx_drops', 0),
                    'rx_fcs_error': sfp.get('rx_fcs_error', 0),
                    'rx_align_error': sfp.get('rx_align_error', 0),
                    'rx_fragment': sfp.get('rx_fragment', 0),
                    'rx_overflow': sfp.get('rx_overflow', 0),
                    'rx_too_long': sfp.get('rx_too_long', 0),
                    'rx_too_short': sfp.get('rx_too_short', 0),
                    'tx_collision': sfp.get('tx_collision', 0),
                    'tx_excessive_collision': sfp.get('tx_excessive_collision', 0),
                    'tx_late_collision': sfp.get('tx_late_collision', 0)
                }
                print(f"  {Fore.GREEN}[BASELINE SET]{Style.RESET_ALL} {device['hostname']:20s} - {port_key}")
        
        print(f"\n{Fore.GREEN}{Style.BRIGHT}Counters reset to 0 (baseline stored){Style.RESET_ALL}")
        print(f"{Fore.GREEN}All statistics will now show values since reset{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
        time.sleep(3)  # Give user time to see the message
        return len(self.baseline_stats)
    
    def calculate_error_rate(self, device_ip: str, port: str, errors: int, packets: int) -> float:
        """Calculate error rate per million packets"""
        if packets <= 0:
            return 0.0
        return (errors / packets) * 1_000_000
    
    def get_packet_size_distribution(self, device_ip: str, port: str) -> dict:
        """Get packet size distribution percentages"""
        key = f"{device_ip}_{port}"
        if key not in self.packet_size_dist:
            return {}
        
        dist = self.packet_size_dist[key]
        total = sum(dist.values())
        if total == 0:
            return {}
        
        return {size: (count / total * 100) for size, count in dist.items()}
    
    def get_traffic_rate(self, device_ip: str, port: str, current_rx: int, current_tx: int) -> tuple:
        """Calculate traffic rate in Mbps based on time difference"""
        current_time = time.time()
        key = f"{device_ip}_{port}"
        
        # Initialize if not exists
        if key not in self.previous_stats:
            self.previous_stats[key] = {'rx': current_rx, 'tx': current_tx}
            self.last_collection_time[key] = current_time
            return (0.0, 0.0)
        
        # Calculate time difference
        time_diff = current_time - self.last_collection_time[key]
        if time_diff <= 0:
            return (0.0, 0.0)
        
        # Calculate byte difference
        rx_diff = current_rx - self.previous_stats[key]['rx']
        tx_diff = current_tx - self.previous_stats[key]['tx']
        
        # Handle counter wraparound
        if rx_diff < 0:
            rx_diff = current_rx
        if tx_diff < 0:
            tx_diff = current_tx
        
        # Calculate rate in Mbps
        rx_mbps = (rx_diff * 8) / (time_diff * 1_000_000)
        tx_mbps = (tx_diff * 8) / (time_diff * 1_000_000)
        
        # Update stored values
        self.previous_stats[key] = {'rx': current_rx, 'tx': current_tx}
        self.last_collection_time[key] = current_time
        
        return (rx_mbps, tx_mbps)
    
    def get_delta_value(self, device_ip: str, port: str, field: str, current_value):
        """Calculate delta from baseline if exists"""
        if not self.baseline_stats or device_ip not in self.baseline_stats:
            return current_value
        
        if port not in self.baseline_stats[device_ip]:
            return current_value
        
        baseline = self.baseline_stats[device_ip][port].get(field, 0)
        return current_value - baseline
    
    def update_error_history(self):
        """Update error history for rate calculation"""
        current_time = time.time()
        
        for device in self.results:
            if device['error']:
                continue
            
            device_key = device['host']
            if device_key not in self.error_history:
                self.error_history[device_key] = {}
            
            for sfp in device['sfp_ports']:
                port_key = sfp['interface']
                if port_key not in self.error_history[device_key]:
                    self.error_history[device_key][port_key] = []
                
                # Get total error count
                total_errors = (
                    sfp.get('rx_fcs_error', 0) +
                    sfp.get('rx_errors', 0) +
                    sfp.get('rx_fragment', 0) +
                    sfp.get('rx_align_error', 0)
                )
                
                # Add to history with timestamp
                self.error_history[device_key][port_key].append({
                    'time': current_time,
                    'errors': total_errors
                })
                
                # Keep only last 60 seconds of history
                cutoff_time = current_time - 60
                self.error_history[device_key][port_key] = [
                    h for h in self.error_history[device_key][port_key]
                    if h['time'] > cutoff_time
                ]
    
    def get_error_count(self, device_ip: str, port: str, seconds: int):
        """Calculate total error count over specified seconds"""
        if device_ip not in self.error_history or port not in self.error_history[device_ip]:
            return 0
        
        history = self.error_history[device_ip][port]
        if len(history) < 2:
            return 0
        
        current_time = time.time()
        cutoff_time = current_time - seconds
        
        # Find data points within time range
        recent_data = [h for h in history if h['time'] > cutoff_time]
        if len(recent_data) < 2:
            return 0
        
        # Calculate total errors in time period
        # Get the oldest value within the time window
        oldest_in_window = recent_data[0]['errors']
        # Get the most recent value
        newest_in_window = recent_data[-1]['errors']
        
        # Return the difference (new errors that happened in this time window)
        error_diff = newest_in_window - oldest_in_window
        return max(0, error_diff)  # Ensure non-negative
    
    def print_monitoring_summary(self, device_count=0):
        """Print compact monitoring summary for terminal - errors and rates only"""
        # Build entire output in memory first (double buffering)
        output_lines = []
        
        # Enable ANSI escape codes on Windows 10+
        if os.name == 'nt':
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                # Enable ANSI escape code processing
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            except:
                pass
        
        # Header with timestamp
        output_lines.append(f"{Fore.CYAN}{Style.BRIGHT}{'='*80}{Style.RESET_ALL}")
        output_lines.append(f"{Fore.CYAN}{Style.BRIGHT}MIKROTIK SFP MONITORING - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        output_lines.append(f"{Fore.YELLOW}Monitoring {device_count} device(s) - Discovery running in background{Style.RESET_ALL}")
        if self.reset_time:
            elapsed = (datetime.now() - self.reset_time).total_seconds()
            output_lines.append(f"{Fore.GREEN}Counters reset {int(elapsed)} seconds ago - showing delta values{Style.RESET_ALL}")
        output_lines.append(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        
        # Show device versions - SORTED BY IP ADDRESS
        output_lines.append(f"\n{Fore.BLUE}{Style.BRIGHT}[DEVICE INFO]{Style.RESET_ALL}")
        output_lines.append(f"{Fore.BLUE}{'-'*80}{Style.RESET_ALL}")
        
        # Sort devices by IP address for consistent ordering
        devices_to_show = []
        for device in self.results:
            if not device['error']:
                devices_to_show.append(device)
        
        # Sort by IP address (convert to tuple of ints for proper sorting)
        def ip_sort_key(device):
            try:
                parts = device['host'].split('.')
                return tuple(int(part) for part in parts)
            except:
                return (999, 999, 999, 999)  # Put invalid IPs at the end
        
        devices_to_show.sort(key=ip_sort_key)
        
        for device in devices_to_show:
            version = device.get('version', 'Unknown')
            rb_version = device.get('routerboard_version', 'Unknown')
            model = device.get('routerboard_model', device.get('board_name', 'Unknown'))
            uptime = device.get('uptime', 'Unknown')
            cpu = device.get('cpu_load', 0)
            
            # Color code CPU load
            cpu_color = Fore.GREEN if cpu < 50 else Fore.YELLOW if cpu < 80 else Fore.RED
            
            output_lines.append(f"{Fore.WHITE}{device['hostname']:20s} ({device['host']:15s}) | "
                  f"RouterOS: {Fore.GREEN}{version:12s}{Fore.WHITE} | "
                  f"Firmware: {Fore.GREEN}{rb_version:8s}{Fore.WHITE} | "
                  f"Model: {Fore.CYAN}{model:15s}{Fore.WHITE} | "
                  f"CPU: {cpu_color}{cpu:3d}%{Style.RESET_ALL}")
        
        # Collect all ports with their status
        all_ports = []
        for device in self.results:
            if device['error']:
                continue
            for sfp in device['sfp_ports']:
                # Get device and port info
                device_ip = device['host']
                port_name = sfp['interface']
                
                # Calculate actual traffic rate in Mbps/s
                rx_mbps, tx_mbps = self.get_traffic_rate(
                    device_ip, port_name,
                    sfp.get('rx_bytes', 0),
                    sfp.get('tx_bytes', 0)
                )
                
                # Calculate delta values for all error types
                rx_errors = self.get_delta_value(device_ip, port_name, 'rx_errors', sfp.get('rx_errors', 0))
                tx_errors = self.get_delta_value(device_ip, port_name, 'tx_errors', sfp.get('tx_errors', 0))
                rx_drops = self.get_delta_value(device_ip, port_name, 'rx_drops', sfp.get('rx_drops', 0))
                tx_drops = self.get_delta_value(device_ip, port_name, 'tx_drops', sfp.get('tx_drops', 0))
                fcs_errors = self.get_delta_value(device_ip, port_name, 'rx_fcs_error', sfp.get('rx_fcs_error', 0))
                align_errors = self.get_delta_value(device_ip, port_name, 'rx_align_error', sfp.get('rx_align_error', 0))
                fragment = self.get_delta_value(device_ip, port_name, 'rx_fragment', sfp.get('rx_fragment', 0))
                overflow = self.get_delta_value(device_ip, port_name, 'rx_overflow', sfp.get('rx_overflow', 0))
                
                # Count total errors (using delta values)
                total_errors = (
                    rx_errors + tx_errors + rx_drops + tx_drops +
                    fcs_errors + align_errors + fragment + overflow
                )
                
                # Calculate error rate per million packets
                total_packets = self.get_delta_value(device_ip, port_name, 'rx_packets', sfp.get('rx_packets', 0)) + \
                                self.get_delta_value(device_ip, port_name, 'tx_packets', sfp.get('tx_packets', 0))
                error_rate = self.calculate_error_rate(device_ip, port_name, total_errors, total_packets)
                
                # Get pause frame counts
                key = f"{device_ip}_{port_name}"
                pause_rx = self.pause_frames.get(key, {}).get('rx', 0)
                pause_tx = self.pause_frames.get(key, {}).get('tx', 0)
                
                # Get queue drops
                queue_drops = self.get_delta_value(device_ip, port_name, 'tx_queue_drop', sfp.get('tx_queue_drop', 0))
                
                # Get link flap/down info
                link_info = self.link_state_history.get(key, {})
                flap_count = link_info.get('flap_count', 0)
                link_downs = self.get_delta_value(device_ip, port_name, 'link_downs', sfp.get('link_downs', 0))
                total_link_downs = sfp.get('link_downs', 0)  # Total count since boot
                
                # Track if port is currently down
                is_down = sfp.get('status', 'unknown') not in ['link-ok', 'running']
                
                all_ports.append({
                    'device': device['hostname'],
                    'ip': device['host'],
                    'port': sfp['interface'],
                    'status': sfp.get('status', 'unknown'),
                    'rate': sfp.get('rate', 'N/A'),
                    'rx_power': sfp.get('sfp_rx_power', 'N/A'),
                    'tx_power': sfp.get('sfp_tx_power', 'N/A'),
                    'temp': sfp.get('sfp_temperature', 'N/A'),
                    'errors': total_errors,
                    'fcs': fcs_errors,
                    'align': align_errors,
                    'fragments': fragment,
                    'rx_errors': rx_errors,
                    'tx_errors': tx_errors,
                    'rx_drops': rx_drops,
                    'tx_drops': tx_drops,
                    'overflow': overflow,
                    'rx_mbps': rx_mbps,  # Use calculated rate
                    'tx_mbps': tx_mbps,   # Use calculated rate
                    'error_rate': error_rate,
                    'pause_frames': pause_rx + pause_tx,
                    'queue_drops': queue_drops,
                    'link_flaps': flap_count,
                    'link_downs': link_downs,
                    'total_link_downs': total_link_downs,
                    'is_down': is_down
                })
        
        # Show ports with link issues
        down_ports = [p for p in all_ports if p['is_down']]
        if down_ports:
            output_lines.append(f"\n{Fore.RED}{Style.BRIGHT}[!] PORTS CURRENTLY DOWN:{Style.RESET_ALL}")
            output_lines.append(f"{Fore.RED}{'-'*80}{Style.RESET_ALL}")
            for port in down_ports:
                output_lines.append(f"{Fore.RED}[DOWN]{Style.RESET_ALL} {port['device']:20s} {port['port']:15s} - "
                      f"Total downs: {port['total_link_downs']}")
        
        # Show ports with errors
        error_ports = [p for p in all_ports if p['errors'] > 0]
        if error_ports:
            output_lines.append(f"\n{Fore.RED}{Style.BRIGHT}[!] PORTS WITH ERRORS:{Style.RESET_ALL}")
            output_lines.append(f"{Fore.RED}{'-'*80}{Style.RESET_ALL}")
            # Sort by errors (descending) but then by IP for consistency when errors are equal
            def error_sort_key(port):
                try:
                    ip_parts = port['ip'].split('.')
                    ip_tuple = tuple(int(part) for part in ip_parts)
                except:
                    ip_tuple = (999, 999, 999, 999)
                return (-port['errors'], ip_tuple, port['port'])  # Negative for descending order
            
            for port in sorted(error_ports, key=error_sort_key):
                if port['errors'] > 1000:
                    status_indicator = f"{Back.RED}{Fore.WHITE}{Style.BRIGHT}[CRITICAL]{Style.RESET_ALL}"
                    color = Fore.RED
                elif port['errors'] > 100:
                    status_indicator = f"{Back.YELLOW}{Fore.BLACK}[WARNING]{Style.RESET_ALL}"
                    color = Fore.YELLOW
                else:
                    status_indicator = f"{Fore.YELLOW}[INFO]{Style.RESET_ALL}"
                    color = Fore.YELLOW
                
                # Calculate error counts for time windows
                errors_10s = self.get_error_count(port['ip'], port['port'], 10)
                errors_60s = self.get_error_count(port['ip'], port['port'], 60)
                
                # Format error counts with color coding
                if errors_10s > 0:
                    if errors_10s > 100:
                        errors_10s_str = f"{Back.RED}{Fore.WHITE}{errors_10s:5d}{Style.RESET_ALL}"
                    elif errors_10s > 10:
                        errors_10s_str = f"{Fore.RED}{errors_10s:5d}{Style.RESET_ALL}"
                    else:
                        errors_10s_str = f"{Fore.YELLOW}{errors_10s:5d}{Style.RESET_ALL}"
                else:
                    errors_10s_str = f"{Fore.GREEN}    0{Style.RESET_ALL}"
                
                if errors_60s > 0:
                    if errors_60s > 500:
                        errors_60s_str = f"{Fore.RED}{errors_60s:5d}{Style.RESET_ALL}"
                    elif errors_60s > 50:
                        errors_60s_str = f"{Fore.YELLOW}{errors_60s:5d}{Style.RESET_ALL}"
                    else:
                        errors_60s_str = f"{Fore.CYAN}{errors_60s:5d}{Style.RESET_ALL}"
                else:
                    errors_60s_str = f"{Fore.GREEN}    0{Style.RESET_ALL}"
                
                # Format error rate
                if port['error_rate'] > 100:
                    rate_str = f"{Fore.RED}{port['error_rate']:.0f} EPM{Style.RESET_ALL}"
                elif port['error_rate'] > 10:
                    rate_str = f"{Fore.YELLOW}{port['error_rate']:.0f} EPM{Style.RESET_ALL}"
                elif port['error_rate'] > 0:
                    rate_str = f"{Fore.GREEN}{port['error_rate']:.1f} EPM{Style.RESET_ALL}"
                else:
                    rate_str = f"{Fore.GREEN}0 EPM{Style.RESET_ALL}"
                
                # Build error details string with color coding
                error_details = []
                if port['fcs'] > 0:
                    fcs_color = Fore.RED if port['fcs'] > 100 else Fore.YELLOW
                    error_details.append(f"{fcs_color}FCS:{port['fcs']}{Style.RESET_ALL}")
                if port['align'] > 0:
                    align_color = Fore.RED if port['align'] > 50 else Fore.YELLOW
                    error_details.append(f"{align_color}Align:{port['align']}{Style.RESET_ALL}")
                if port['rx_drops'] > 0:
                    drop_color = Fore.RED if port['rx_drops'] > 100 else Fore.YELLOW
                    error_details.append(f"{drop_color}RX-Drop:{port['rx_drops']}{Style.RESET_ALL}")
                if port['tx_drops'] > 0:
                    drop_color = Fore.RED if port['tx_drops'] > 100 else Fore.YELLOW
                    error_details.append(f"{drop_color}TX-Drop:{port['tx_drops']}{Style.RESET_ALL}")
                if port['fragments'] > 0:
                    frag_color = Fore.RED if port['fragments'] > 50 else Fore.YELLOW
                    error_details.append(f"{frag_color}Frag:{port['fragments']}{Style.RESET_ALL}")
                if port['overflow'] > 0:
                    over_color = Fore.RED if port['overflow'] > 10 else Fore.YELLOW
                    error_details.append(f"{over_color}Ovflw:{port['overflow']}{Style.RESET_ALL}")
                
                error_detail_str = ' | '.join(error_details) if error_details else f"{Fore.YELLOW}Mixed errors{Style.RESET_ALL}"
                
                output_lines.append(f"{status_indicator} {color}{port['device']:20s} {port['port']:15s}{Style.RESET_ALL} | "
                      f"Total: {Fore.WHITE}{port['errors']:7d}{Style.RESET_ALL} | "
                      f"Last 10s: {errors_10s_str} | Last 60s: {errors_60s_str} | "
                      f"Rate: {rate_str}")
                output_lines.append(f"    {Fore.CYAN}Error Breakdown:{Style.RESET_ALL} {error_detail_str}")
        
        # Show all ports status in compact format
        output_lines.append(f"\n{Fore.GREEN}{Style.BRIGHT}[*] ALL PORTS STATUS:{Style.RESET_ALL}")
        output_lines.append(f"{Fore.GREEN}{'-'*165}{Style.RESET_ALL}")
        # Build header with proper spacing - adjusted to match data alignment
        header = (f"{Fore.WHITE}{Style.BRIGHT}"
                  f"{'Device':<20} "  
                  f"{'Port':<15} "  
                  f"{'Status':<10} "   
                  f"{'Traffic(Mbps)':<16} " 
                  f"{'Rate':<8} "     
                  f"{'Temp':<5} "     
                  f"{'Power(dBm)':<16} "  
                  f"{'Errors':<9} "   
                  f"{'FCS':<5} "     
                  f"{'Q-Drop':<6} "  
                  f"{'L-Down':<7} "  # Link Downs
                  f"{'Flaps':<5}"    
                  f"{Style.RESET_ALL}")
        output_lines.append(header)
        output_lines.append(f"{Fore.WHITE}{'-'*165}{Style.RESET_ALL}")
        
        # Sort ports by IP address first, then by port name
        def port_sort_key(port):
            try:
                ip_parts = port['ip'].split('.')
                ip_tuple = tuple(int(part) for part in ip_parts)
            except:
                ip_tuple = (999, 999, 999, 999)
            return (ip_tuple, port['port'])
        
        for port in sorted(all_ports, key=port_sort_key):
            # Use the pre-calculated traffic rates
            rx_mbps = port.get('rx_mbps', 0)
            tx_mbps = port.get('tx_mbps', 0)
            
            # Format traffic string with color coding
            traffic_str = f"{rx_mbps:.1f}/{tx_mbps:.1f}"
            total_mbps = rx_mbps + tx_mbps
            
            # Color code traffic based on utilization
            if total_mbps > 8000:  # >8Gbps
                traffic_color = Fore.RED
            elif total_mbps > 5000:  # >5Gbps
                traffic_color = Fore.MAGENTA
            elif total_mbps > 1000:  # >1Gbps
                traffic_color = Fore.YELLOW
            elif total_mbps > 100:  # >100Mbps
                traffic_color = Fore.CYAN
            elif total_mbps > 10:  # >10Mbps
                traffic_color = Fore.GREEN
            elif total_mbps > 0:
                traffic_color = Fore.WHITE
            else:
                traffic_color = Fore.BLUE  # No traffic
            
            # Color code based on status
            if port['status'] == 'link-ok':
                status_color = Fore.GREEN
                status_text = port['status']
            elif 'no-link' in port['status']:
                status_color = Fore.YELLOW
                status_text = port['status']
            else:
                status_color = Fore.RED
                status_text = port['status']
            
            # Color code errors
            if port['errors'] > 0:
                error_color = Fore.RED if port['errors'] > 100 else Fore.YELLOW
                error_str = f"{error_color}{port['errors']}{Style.RESET_ALL}"
            else:
                error_str = f"{Fore.GREEN}0{Style.RESET_ALL}"
            
            # Show FCS errors separately
            if port['fcs'] > 0:
                fcs_color = Fore.RED if port['fcs'] > 50 else Fore.YELLOW if port['fcs'] > 10 else Fore.WHITE
                fcs_str = f"{fcs_color}{port['fcs']}{Style.RESET_ALL}"
            else:
                fcs_str = f"{Fore.GREEN}0{Style.RESET_ALL}"
            
            # Color code temperature with fixed width
            temp_val = port['temp']
            if temp_val != 'N/A':
                try:
                    temp_num = int(temp_val)
                    if temp_num > 70:
                        temp_color = Fore.RED
                    elif temp_num > 60:
                        temp_color = Fore.YELLOW
                    else:
                        temp_color = Fore.GREEN
                    # Format with fixed width for alignment - keep it simple
                    temp_str = f"{temp_color}{temp_val}C{Style.RESET_ALL}"
                except:
                    temp_str = f"{temp_val}C"
            else:
                temp_str = "N/A"
            
            # Format power levels in dBm with color coding
            rx_pwr = port['rx_power']
            tx_pwr = port['tx_power']
            
            # Format and color code power levels
            if rx_pwr != 'N/A' and tx_pwr != 'N/A':
                try:
                    # MikroTik usually provides power in dBm as string
                    rx_val = float(str(rx_pwr).replace('dBm', ''))
                    tx_val = float(str(tx_pwr).replace('dBm', ''))
                    
                    # Color code RX power to match legend
                    if rx_val < -30:  # Very weak signal
                        rx_color = Fore.RED
                    elif rx_val >= -30 and rx_val < -20:  # Weak signal (-30 to -20)
                        rx_color = Fore.YELLOW
                    elif rx_val >= -20 and rx_val < -7:  # Good signal (-20 to -7)
                        rx_color = Fore.GREEN
                    elif rx_val >= -7 and rx_val < -3:  # Strong signal (-7 to -3)
                        rx_color = Fore.CYAN
                    else:  # Very strong (>= -3, might be too high)
                        rx_color = Fore.MAGENTA
                    
                    # Color code TX power (typical range -10 to 3 dBm)
                    if tx_val < -10:  # Very weak
                        tx_color = Fore.RED
                    elif tx_val < -5:  # Weak
                        tx_color = Fore.YELLOW
                    elif tx_val < 0:  # Good
                        tx_color = Fore.GREEN
                    else:  # Strong
                        tx_color = Fore.CYAN
                    
                    # Format power with fixed width for alignment
                    # Ensure both RX and TX use exactly 5 characters (e.g., "-12.5", " -3.4")
                    rx_formatted = f"{rx_val:5.1f}"  # This ensures 5 chars total
                    tx_formatted = f"{tx_val:5.1f}"  # This ensures 5 chars total
                    rx_str = f"{rx_color}{rx_formatted}{Style.RESET_ALL}"
                    tx_str = f"{tx_color}{tx_formatted}{Style.RESET_ALL}"
                    power_str = f"{rx_str}/{tx_str}"  # Total visible width = 11 (5 + 1 + 5)
                except:
                    # If parsing fails, show raw values with fixed width
                    power_str = f"{str(rx_pwr)[:6]:6}/{str(tx_pwr)[:6]:6}"
            else:
                power_str = f"{'N/A':^13}"
            
            # Color code rate
            if '10Gbps' in port['rate']:
                rate_color = Fore.CYAN
            elif '1Gbps' in port['rate']:
                rate_color = Fore.GREEN
            else:
                rate_color = Fore.WHITE
            
            # Format queue drops
            if port['queue_drops'] > 100:
                qdrop_str = f"{Fore.RED}{port['queue_drops']}{Style.RESET_ALL}"
            elif port['queue_drops'] > 10:
                qdrop_str = f"{Fore.YELLOW}{port['queue_drops']}{Style.RESET_ALL}"
            elif port['queue_drops'] > 0:
                qdrop_str = f"{Fore.WHITE}{port['queue_drops']}{Style.RESET_ALL}"
            else:
                qdrop_str = f"{Fore.GREEN}0{Style.RESET_ALL}"
            
            # Format link downs
            if port['link_downs'] > 10:
                ldown_str = f"{Fore.RED}{port['link_downs']}{Style.RESET_ALL}"
            elif port['link_downs'] > 5:
                ldown_str = f"{Fore.YELLOW}{port['link_downs']}{Style.RESET_ALL}"
            elif port['link_downs'] > 0:
                ldown_str = f"{Fore.WHITE}{port['link_downs']}{Style.RESET_ALL}"
            else:
                ldown_str = f"{Fore.GREEN}0{Style.RESET_ALL}"
            
            # Format link flaps
            if port['link_flaps'] > 5:
                flap_str = f"{Fore.RED}{port['link_flaps']}{Style.RESET_ALL}"
            elif port['link_flaps'] > 0:
                flap_str = f"{Fore.YELLOW}{port['link_flaps']}{Style.RESET_ALL}"
            else:
                flap_str = f"{Fore.GREEN}0{Style.RESET_ALL}"
            
            # Build formatted row with proper alignment
            # The strings already contain color codes, so just print with spaces
            # Adjust spacing to move errors and following columns to the right
            output_lines.append(f"{Fore.WHITE}{port['device']:<20}{Style.RESET_ALL} "
                  f"{Fore.WHITE}{port['port']:<15}{Style.RESET_ALL} "
                  f"{status_color}{status_text:<10}{Style.RESET_ALL} "
                  f"{traffic_color}{traffic_str:<16}{Style.RESET_ALL} "
                  f"{rate_color}{port['rate']:<8}{Style.RESET_ALL} "
                  f"{temp_str}   "  # Add 3 spaces after temp
                  f"{power_str}     "  # Add 5 spaces after power
                  f"{error_str}      "  # Keep 6 spaces
                  f"{fcs_str}    "  # Keep 4 spaces
                  f"{qdrop_str}     "  # Keep 5 spaces
                  f"{ldown_str}       "  # Add 7 spaces for link downs
                  f"{flap_str}")
        
        # Show ports with frequent link downs
        unstable_ports = [p for p in all_ports if p['link_downs'] > 0 or p['link_flaps'] > 0]
        if unstable_ports:
            output_lines.append(f"\n{Fore.YELLOW}{Style.BRIGHT}[!] LINK STABILITY ISSUES:{Style.RESET_ALL}")
            for port in sorted(unstable_ports, key=lambda x: x['link_downs'] + x['link_flaps'], reverse=True)[:5]:
                stability_info = []
                if port['link_downs'] > 0:
                    stability_info.append(f"Link Downs: {port['link_downs']}")
                if port['link_flaps'] > 0:
                    stability_info.append(f"Flaps: {port['link_flaps']}")
                if port['total_link_downs'] > 0:
                    stability_info.append(f"Total Downs Since Boot: {port['total_link_downs']}")
                output_lines.append(f"  {port['device']:20s} {port['port']:15s} - {', '.join(stability_info)}")
        
        # Show packet size distribution for ports with traffic
        active_ports = [p for p in all_ports if p['rx_mbps'] + p['tx_mbps'] > 10]  # Only ports with >10Mbps
        if active_ports and len(active_ports) <= 3:  # Show for up to 3 active ports
            output_lines.append(f"\n{Fore.BLUE}{Style.BRIGHT}[*] PACKET SIZE DISTRIBUTION:{Style.RESET_ALL}")
            for port in active_ports[:3]:
                dist = self.get_packet_size_distribution(port['ip'], port['port'])
                if dist:
                    line = f"  {port['device']} {port['port']}:"
                    for size, percent in dist.items():
                        if percent > 1:  # Only show sizes with >1%
                            color = Fore.YELLOW if percent > 50 else Fore.CYAN if percent > 20 else Fore.WHITE
                            line += f" {color}{size}:{percent:.0f}%{Style.RESET_ALL}"
                    output_lines.append(line)
        
        # Show ports with pause frames
        pause_ports = [p for p in all_ports if p['pause_frames'] > 0]
        if pause_ports:
            output_lines.append(f"\n{Fore.YELLOW}{Style.BRIGHT}[!] FLOW CONTROL ACTIVE (Pause Frames):{Style.RESET_ALL}")
            for port in pause_ports[:5]:  # Show up to 5 ports
                output_lines.append(f"  {port['device']:20s} {port['port']:15s} - {port['pause_frames']} frames")
        
        # Show detailed error breakdown for ports with significant errors
        significant_error_ports = [p for p in all_ports if p['errors'] > 10]
        if significant_error_ports:
            output_lines.append(f"\n{Fore.YELLOW}{Style.BRIGHT}[!] ERROR DETAILS:{Style.RESET_ALL}")
            for port in significant_error_ports[:5]:  # Show up to 5 ports
                error_types = []
                if port['fcs'] > 0:
                    error_types.append(f"FCS: {port['fcs']}")
                if port['align'] > 0:
                    error_types.append(f"Alignment: {port['align']}")
                if port['rx_drops'] > 0:
                    error_types.append(f"RX-Drops: {port['rx_drops']}")
                if port['tx_drops'] > 0:
                    error_types.append(f"TX-Drops: {port['tx_drops']}")
                if port['fragments'] > 0:
                    error_types.append(f"Fragments: {port['fragments']}")
                if port['overflow'] > 0:
                    error_types.append(f"Overflow: {port['overflow']}")
                
                output_lines.append(f"  {port['device']:20s} {port['port']:15s} - {', '.join(error_types)}")
        
        # Show legend
        output_lines.append(f"\n{Fore.CYAN}{Style.BRIGHT}[*] LEGEND:{Style.RESET_ALL}")
        output_lines.append(f"  Traffic (RX/TX Mbps): {Fore.BLUE}* Idle{Style.RESET_ALL} | "
              f"{Fore.GREEN}* 10+{Style.RESET_ALL} | "
              f"{Fore.CYAN}* 100+{Style.RESET_ALL} | "
              f"{Fore.YELLOW}* 1G+{Style.RESET_ALL} | "
              f"{Fore.MAGENTA}* 5G+{Style.RESET_ALL} | "
              f"{Fore.RED}* 8G+{Style.RESET_ALL}")
        output_lines.append(f"  Power RX (dBm): {Fore.RED}* <-30 (Very Weak){Style.RESET_ALL} | "
              f"{Fore.YELLOW}* -30 to -20 (Weak){Style.RESET_ALL} | "
              f"{Fore.GREEN}* -20 to -7 (Good){Style.RESET_ALL} | "
              f"{Fore.CYAN}* -7 to -3 (Strong){Style.RESET_ALL} | "
              f"{Fore.MAGENTA}* >-3 (Very Strong){Style.RESET_ALL}")
        output_lines.append(f"  Power TX (dBm): {Fore.RED}* <-10 (Very Weak){Style.RESET_ALL} | "
              f"{Fore.YELLOW}* -10 to -5 (Weak){Style.RESET_ALL} | "
              f"{Fore.GREEN}* -5 to 0 (Good){Style.RESET_ALL} | "
              f"{Fore.CYAN}* >0 (Strong){Style.RESET_ALL}")
        output_lines.append(f"  Error Types: FCS = Frame Check Sequence | Q-Drop = Queue Drops | L-Down = Link Down Events | Flaps = Link State Changes")
        output_lines.append(f"  EPM = Errors Per Million packets | Align = Alignment Errors | Frag = Fragmented Packets")
        
        output_lines.append(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        output_lines.append(f"{Fore.YELLOW}Press 'R' to reset counters | Ctrl+C to stop monitoring{Style.RESET_ALL}")
        
        # Now write everything at once with cursor positioning
        # Clear screen and move cursor to home
        output = '\033[H\033[2J' + '\n'.join(output_lines)
        print(output, end='', flush=True)
    
    def print_results(self):
        """Print collected results to terminal"""
        # Table format only
        print("\n" + "="*100)
        print("SFP PORT STATISTICS SUMMARY")
        print("="*100)
        
        # First, show ports with errors at the top
        error_summary = []
        for device in self.results:
                if device['error']:
                    continue
                for sfp in device['sfp_ports']:
                    total_errors = (
                        sfp.get('rx_errors', 0) +
                        sfp.get('tx_errors', 0) +
                        sfp.get('rx_drops', 0) +
                        sfp.get('tx_drops', 0) +
                        sfp.get('rx_fcs_error', 0) +
                        sfp.get('rx_align_error', 0) +
                        sfp.get('rx_fragment', 0) +
                        sfp.get('rx_overflow', 0) +
                        sfp.get('rx_too_long', 0) +
                        sfp.get('rx_too_short', 0) +
                        sfp.get('tx_collision', 0) +
                        sfp.get('tx_excessive_collision', 0) +
                        sfp.get('tx_late_collision', 0)
                    )
                    if total_errors > 0:
                        # Get delta values for error summary
                        device_ip = device['host']
                        port_name = sfp['interface']
                        
                        error_summary.append({
                            'device': device['hostname'],
                            'ip': device['host'],
                            'interface': sfp['interface'],
                            'errors': {
                                'FCS': self.get_delta_value(device_ip, port_name, 'rx_fcs_error', sfp.get('rx_fcs_error', 0)),
                                'Align': self.get_delta_value(device_ip, port_name, 'rx_align_error', sfp.get('rx_align_error', 0)),
                                'RX Errors': self.get_delta_value(device_ip, port_name, 'rx_errors', sfp.get('rx_errors', 0)),
                                'RX Drops': self.get_delta_value(device_ip, port_name, 'rx_drops', sfp.get('rx_drops', 0)),
                                'TX Errors': self.get_delta_value(device_ip, port_name, 'tx_errors', sfp.get('tx_errors', 0)),
                                'TX Drops': self.get_delta_value(device_ip, port_name, 'tx_drops', sfp.get('tx_drops', 0)),
                                'Fragment': self.get_delta_value(device_ip, port_name, 'rx_fragment', sfp.get('rx_fragment', 0)),
                                'Overflow': self.get_delta_value(device_ip, port_name, 'rx_overflow', sfp.get('rx_overflow', 0)),
                                'Too Long': self.get_delta_value(device_ip, port_name, 'rx_too_long', sfp.get('rx_too_long', 0)),
                                'Too Short': self.get_delta_value(device_ip, port_name, 'rx_too_short', sfp.get('rx_too_short', 0)),
                                'Collisions': self.get_delta_value(device_ip, port_name, 'tx_collision', sfp.get('tx_collision', 0)) + 
                                            self.get_delta_value(device_ip, port_name, 'tx_excessive_collision', sfp.get('tx_excessive_collision', 0)) + 
                                            self.get_delta_value(device_ip, port_name, 'tx_late_collision', sfp.get('tx_late_collision', 0))
                            },
                            'total_errors': total_errors
                        })
        
        # Print error summary if errors found
        if error_summary:
            print("\n" + "!"*80)
            print("!!! ATTENTION: PORTS WITH ERRORS DETECTED !!!")
            print("!"*80)
            # Sort by total errors descending
            error_summary.sort(key=lambda x: x['total_errors'], reverse=True)
            
            for err in error_summary:
                print(f"\n>>> {err['device']} ({err['ip']}) - Port: {err['interface']}")
                print(f"    TOTAL ERRORS: {err['total_errors']:,}")
                # Show only non-zero error types
                error_details = []
                for err_type, count in err['errors'].items():
                    if count > 0:
                        error_details.append(f"{err_type}: {count:,}")
                if error_details:
                    print(f"    ERROR BREAKDOWN: {', '.join(error_details)}")
                
                # Add severity indicator
                if err['total_errors'] > 1000:
                    print("    >>> CRITICAL: High error rate - check cable/SFP immediately!")
                elif err['total_errors'] > 100:
                    print("    >>> WARNING: Moderate errors - monitor closely")
                else:
                    print("    >>> INFO: Low error count - may be transient")
            
            print("\n" + "!"*80)
            print()
        else:
            print("\n" + "="*80)
            print("=== SUCCESS: No errors detected on any SFP ports ===")
            print("="*80)
        
        for device in self.results:
            if device['error']:
                print(f"\n[ERROR] {device['host']} - {device['error']}")
                continue
            
            print(f"\nDevice: {device['hostname']} ({device['host']})")
            print("-"*80)
            
            if not device['sfp_ports']:
                print("  No SFP ports found or no SFP modules installed")
            else:
                for sfp in device['sfp_ports']:
                    print(f"\n  Interface: {sfp['interface']}")
                    print(f"    Status: {sfp['status']}")
                    print(f"    Vendor: {sfp['sfp_vendor']}")
                    print(f"    Part Number: {sfp['sfp_part_number']}")
                    print(f"    Wavelength: {sfp['sfp_wavelength']} nm")
                    print(f"    Temperature: {sfp['sfp_temperature']}")
                    print(f"    RX Power: {sfp['sfp_rx_power']}")
                    print(f"    TX Power: {sfp['sfp_tx_power']}")
                    print(f"    Rate: {sfp['rate']}")
                    
                    if 'rx_bytes' in sfp:
                        print(f"    Traffic Statistics:")
                        print(f"      RX Bytes: {sfp.get('rx_bytes', 0):,}")
                        print(f"      RX Packets: {sfp.get('rx_packets', 0):,}")
                        print(f"      TX Bytes: {sfp.get('tx_bytes', 0):,}")
                        print(f"      TX Packets: {sfp.get('tx_packets', 0):,}")
                        
                        print(f"    Error Statistics:")
                        print(f"      RX Errors: {sfp.get('rx_errors', 0):,}")
                        print(f"      RX Drops: {sfp.get('rx_drops', 0):,}")
                        print(f"      TX Errors: {sfp.get('tx_errors', 0):,}")
                        print(f"      TX Drops: {sfp.get('tx_drops', 0):,}")
                        print(f"      FCS Errors: {sfp.get('rx_fcs_error', 0):,}")
                        print(f"      Alignment Errors: {sfp.get('rx_align_error', 0):,}")
                        print(f"      Fragments: {sfp.get('rx_fragment', 0):,}")
                        print(f"      Overflow: {sfp.get('rx_overflow', 0):,}")
                        print(f"      Too Long: {sfp.get('rx_too_long', 0):,}")
                        print(f"      Too Short: {sfp.get('rx_too_short', 0):,}")
                        
                        if sfp.get('tx_collision', 0) > 0 or sfp.get('tx_late_collision', 0) > 0:
                            print(f"    Collision Statistics:")
                            print(f"      Collisions: {sfp.get('tx_collision', 0):,}")
                            print(f"      Excessive Collisions: {sfp.get('tx_excessive_collision', 0):,}")
                            print(f"      Late Collisions: {sfp.get('tx_late_collision', 0):,}")
                        
                        # Show packet size distribution if any packets received
                        if sfp.get('rx_packets', 0) > 0:
                            print(f"    Packet Size Distribution:")
                            print(f"      64 bytes: {sfp.get('rx_64', 0):,}")
                            print(f"      65-127 bytes: {sfp.get('rx_65_127', 0):,}")
                            print(f"      128-255 bytes: {sfp.get('rx_128_255', 0):,}")
                            print(f"      256-511 bytes: {sfp.get('rx_256_511', 0):,}")
                            print(f"      512-1023 bytes: {sfp.get('rx_512_1023', 0):,}")
                            print(f"      1024-1518 bytes: {sfp.get('rx_1024_1518', 0):,}")
                            print(f"      1519+ bytes: {sfp.get('rx_1519_max', 0):,}")
        
        print("\n" + "="*100)
        
        # Summary
        total_devices = len(self.results)
        successful = sum(1 for d in self.results if not d['error'])
        total_sfp = sum(len(d['sfp_ports']) for d in self.results)
        
        print(f"\nSummary: {successful}/{total_devices} devices queried successfully")
        print(f"Total SFP ports found: {total_sfp}")


def main():
    parser = argparse.ArgumentParser(description='Monitor SFP port statistics from MikroTik routers using MNDP discovery')
    parser.add_argument('-u', '--username', required=True, help='RouterOS username')
    parser.add_argument('-p', '--password', required=True, help='RouterOS password')
    parser.add_argument('--port', type=int, default=8728, help='RouterOS API port (default: 8728)')
    parser.add_argument('-w', '--workers', type=int, default=5, 
                       help='Maximum concurrent connections (default: 5)')
    parser.add_argument('--interval', type=int, default=1, help='Refresh interval in seconds (default: 1)')
    parser.add_argument('-c', '--config', type=str, default='mikrotik_hosts.txt',
                       help='Path to hosts configuration file (default: mikrotik_hosts.txt)')
    parser.add_argument('--no-discovery', action='store_true',
                       help='Disable MNDP discovery and only use config file')
    
    args = parser.parse_args()
    
    # Initialize collector
    collector = MikroTikSFPCollector(
        username=args.username,
        password=args.password,
        port=args.port,
        ssh_port=22,
        use_ssh=False
    )
    
    # Start with continuous discovery and monitoring
    print("Starting MikroTik SFP Monitor with continuous device discovery...")
    print(f"Refresh interval: {args.interval} second(s)")
    print("Press 'R' to reset counters, Ctrl+C to stop...\n")
    
    # Load hosts from config file first
    print(f"Loading hosts from configuration file: {args.config}")
    config_hosts = collector.load_hosts_from_file(args.config)
    
    # Shared list of discovered hosts (thread-safe)
    discovered_hosts = set(config_hosts)  # Initialize with config hosts
    hosts_lock = threading.Lock()
    
    if config_hosts:
        print(f"  Loaded {len(config_hosts)} host(s) from config file")
    
    if args.no_discovery:
        print("  MNDP discovery disabled - using only config file hosts")
    elif not config_hosts:
        print("  No hosts found in config file, relying on MNDP discovery")
    else:
        print("  Will also use MNDP discovery to find additional devices")
    
    # Discovery thread - continuously discovers devices (skip if disabled)
    def continuous_discovery():
        discovery_count = 0
        while True:
            try:
                # More aggressive discovery for first minute
                if discovery_count < 12:  # First 12 attempts (1 minute)
                    timeout = 8
                    sleep_time = 5  # Every 5 seconds initially
                else:
                    timeout = 5
                    sleep_time = 15  # Every 15 seconds after initial period
                
                devices = collector.discover_mikrotik_devices(timeout=timeout)
                if devices:
                    with hosts_lock:
                        for device in devices:
                            if device['ip'] not in discovered_hosts:
                                discovered_hosts.add(device['ip'])
                                print(f"\n[NEW DEVICE] Found: {device['identity']} ({device['ip']})")
                discovery_count += 1
                time.sleep(sleep_time)
            except:
                time.sleep(5)
    
    # Start discovery thread only if not disabled
    if not args.no_discovery:
        discovery_thread = threading.Thread(target=continuous_discovery, daemon=True)
        discovery_thread.start()
        
        # Initial discovery with longer timeout - do it twice for better coverage
        print("Performing initial device discovery (this may take up to 30 seconds)...")
        for attempt in range(2):
            devices = collector.discover_mikrotik_devices(timeout=10)
            if devices:
                for device in devices:
                    if device['ip'] not in discovered_hosts:
                        discovered_hosts.add(device['ip'])
                        print(f"  - {device['identity']} ({device['ip']}")
            if attempt == 0:
                time.sleep(2)  # Short pause between attempts
    
    # Start monitoring even if no devices initially found
    if True:  # Always start monitoring
        time.sleep(2)
        
        # Flag for reset request
        reset_requested = threading.Event()
        
        # Keyboard listener thread (Windows only for now)
        def keyboard_listener():
            while True:
                try:
                    if os.name == 'nt' and msvcrt.kbhit():
                        key = msvcrt.getch()
                        if key in [b'r', b'R']:
                            reset_requested.set()
                    time.sleep(0.1)
                except:
                    break
        
        if os.name == 'nt':
            kb_thread = threading.Thread(target=keyboard_listener, daemon=True)
            kb_thread.start()
        
        try:
            iteration = 0
            
            while True:
                # Get current list of hosts
                with hosts_lock:
                    current_hosts = list(discovered_hosts)
                
                # Skip if no hosts discovered yet
                if not current_hosts:
                    print("\rWaiting for devices to be discovered...", end="")
                    time.sleep(1)
                    continue
                
                # Check for reset request
                if reset_requested.is_set():
                    reset_requested.clear()
                    # Don't clear screen here - let the summary function handle it
                    collector.reset_interface_counters(current_hosts)
                    iteration = 0  # Reset iteration counter
                    continue
                
                # Collect stats
                collector.results = []  # Clear previous results
                collector.collect_from_hosts(current_hosts, max_workers=args.workers, quiet=True)
                
                # Update error history for rate calculation
                collector.update_error_history()
                
                # Show compact monitoring view in terminal
                collector.print_monitoring_summary(device_count=len(current_hosts))
                
                iteration += 1
                
                # Check for keyboard input during sleep
                for _ in range(int(args.interval * 10)):
                    if reset_requested.is_set():
                        break
                    time.sleep(0.1)
                
        except KeyboardInterrupt:
            print("\n\nMonitoring stopped by user.")
    else:
        print("No hosts to connect to")


if __name__ == '__main__':
    main()