# MikroTik SFP Statistics Monitor

A comprehensive Python tool for monitoring SFP/SFP+ port statistics across multiple MikroTik routers in real-time. Features automatic device discovery, error tracking, and software-based counter reset functionality.

## Features

- **Automatic Device Discovery**: Uses MNDP (MikroTik Neighbor Discovery Protocol) to automatically find routers on the network
- **Real-time Monitoring**: Continuous monitoring mode with 1-second refresh rate
- **Error Tracking**: Comprehensive error statistics including FCS, alignment, fragments, collisions, etc.
- **Time-based Error Analysis**: Shows error counts for last 10 seconds and last minute
- **Software Counter Reset**: Press 'R' to reset counters with baseline tracking (works around API limitations)
- **Visual Indicators**: Color-coded display for easy identification of issues
- **Device Information**: Shows firmware version, RouterBOARD version, and system details
- **Multiple Output Formats**: Terminal display, JSON, and CSV output
- **Sorted Display**: Devices sorted by IP address for consistent viewing

## Requirements

- Python 3.6+
- MikroTik routers with API enabled
- Network access to routers (API port 8728)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/mikrotik-sfp-monitor.git
cd mikrotik-sfp-monitor
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Configure your MikroTik hosts (optional but recommended):
Create or edit `mikrotik_hosts.txt`:
```
# MikroTik hosts configuration file
# Add one IP address per line
# Lines starting with # are comments
10.77.8.1
10.77.9.3
10.77.9.4
192.168.1.1
```

The tool will use both the configuration file and MNDP discovery by default.

## Usage

### Basic Usage

Collect statistics once from all discovered devices:
```bash
python mikrotik_sfp_stats.py -u admin -p "your_password"
```

### Continuous Monitoring Mode

Start real-time monitoring with 1-second refresh:
```bash
python mikrotik_sfp_stats.py -u admin -p "your_password"
```

Monitor only devices from config file (no discovery):
```bash
python mikrotik_sfp_stats.py -u admin -p "your_password" --no-discovery
```

Use custom config file:
```bash
python mikrotik_sfp_stats.py -u admin -p "your_password" -c my_routers.txt
```

In monitoring mode:
- Press **'R'** to reset counters (software-based reset)
- Press **Ctrl+C** to stop monitoring

### Output Formats

JSON output:
```bash
python mikrotik_sfp_stats.py -u admin -p "your_password" -o json > stats.json
```

CSV output:
```bash
python mikrotik_sfp_stats.py -u admin -p "your_password" -o csv > stats.csv
```

### Command-line Options

- `-u, --username`: RouterOS username (required)
- `-p, --password`: RouterOS password (required)
- `-c, --config`: Path to hosts configuration file (default: mikrotik_hosts.txt)
- `--no-discovery`: Disable MNDP discovery and only use config file
- `-w, --workers`: Maximum concurrent connections (default: 5)
- `--interval`: Refresh interval in seconds for monitoring (default: 1)
- `--port`: RouterOS API port (default: 8728)

## Features in Detail

### Error Detection

The tool monitors comprehensive error statistics:
- **FCS Errors**: Frame Check Sequence errors
- **Alignment Errors**: Ethernet frame alignment issues
- **RX/TX Errors**: General receive/transmit errors
- **Drops**: Dropped packets
- **Fragments**: Fragmented packets
- **Collisions**: Various collision types
- **Size Errors**: Too long/too short packets

### Visual Indicators

- **Green**: No errors, good status
- **Yellow**: Warning level (low error count)
- **Red**: Critical (high error count)
- **Cyan**: 10Gbps links
- **Temperature colors**: Green (<60°C), Yellow (60-70°C), Red (>70°C)

### Discovery Methods

1. **MNDP Protocol**: Primary discovery method (like Winbox)
2. **Configuration File**: Fallback using `mikrotik_hosts.txt`
3. **Manual Hosts**: Specify hosts directly via command line

## How It Works

### Device Discovery
The tool uses MNDP (MikroTik Neighbor Discovery Protocol) on UDP port 5678 to automatically discover MikroTik devices on the local network, similar to how Winbox discovers routers.

### Counter Reset
Due to RouterOS API limitations, hardware counters cannot be reset directly. The tool implements a software-based solution:
1. Stores baseline values when 'R' is pressed
2. Calculates and displays delta values from the baseline
3. Maintains error history for rate calculations

### Error Tracking
- Maintains rolling history of error counts
- Calculates error sums for 10-second and 60-second windows
- Shows both total errors and recent error trends

## Troubleshooting

### MNDP Discovery Issues
If not all routers are discovered:
1. Ensure routers have MNDP enabled
2. Check firewall rules allow UDP port 5678
3. Add missing routers to `mikrotik_hosts.txt`

### API Connection Issues
1. Enable API service on RouterOS:
   ```
   /ip service enable api
   ```
2. Check firewall allows API port (8728)
3. Verify username/password have API permissions

### Counter Reset Not Working
The software reset is working correctly if you see "Counters reset X seconds ago - showing delta values" message. Hardware counters cannot be reset via API.

## Example Output

```
================================================================================
MIKROTIK SFP MONITORING - 2024-01-09 15:23:45
================================================================================

[!] PORTS WITH ERRORS:
--------------------------------------------------------------------------------
[FAIL] Router-Core       sfp-sfpplus1    | Total:    1523 | Last 10s:    12 | Last 60s:    89 | FCS:   523
[WARN] Router-Edge       sfp-sfpplus2    | Total:      45 | Last 10s:     0 | Last 60s:     3 | FCS:    12

[*] DEVICE INFORMATION:
--------------------------------------------------------------------------------
Router-Core (10.77.8.1) - RB4011iGS+ | RouterOS 7.11.2 | RB: 7.11.2 | Uptime: 45d 12:34:56

[*] ALL PORTS STATUS:
--------------------------------------------------------------------------------
Device               Port            Status     Rate     Temp   RX/TX Power     Errors
Router-Core          sfp-sfpplus1    up         10Gbps   45C    -6.2/-2.1      1523
Router-Edge          sfp-sfpplus2    up         1Gbps    42C    -7.1/-2.5      45
```

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Author

Created for monitoring MikroTik SFP port statistics in production networks.