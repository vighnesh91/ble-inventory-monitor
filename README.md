# BLE Inventory Monitor

A passive, consent-based Bluetooth LE (BLE) advertisement inventory and wardriving utility. It scans nearby BLE advertisements for authorized troubleshooting without establishing active device connections, tracking movement, or correlating randomized MAC addresses.

## Features

- **Passive Scanning:** Listens for BLE broadcast advertisements using `bleak`.
- **Live HTTP Dashboard:** Built-in web server operating on port `8765` with a live Server-Sent Events (SSE) data stream, interactive searching, and pause capabilities.
- **Durable Logging:** Aggregates logs into rolling CSV files with automatic size-based rotation and historical archive retention.
- **Privacy Enforcement:** Optional mid-octet MAC address masking (`--secure-privacy`) to avoid logging persistent unique hardware identifiers.
- **Data Integrity:** Protects records with canonical SHA-256 or keyed HMAC-SHA-256 integrity tags.
- **Secure Webhooks:** Forwards live event batches via HTTPS POST requests using optional Bearer tokens.

## Prerequisites

- **Python 3.8+**
- **Bleak** (The script will automatically attempt to install `bleak` via `pip` if it is missing)

## Installation

Clone this repository and navigate to the directory:

```bash
git clone https://github.com
cd ble-inventory-monitor
```

## Usage

Run the script with default local settings (saves logs to `iot_wardrive_log.csv` and report to `iot_density_map.html`):

```bash
python ble_inventory.py
```

### Command Line Arguments

| Argument | Default | Description |
| :--- | :--- | :--- |
| `--log <path>` | `iot_wardrive_log.csv` | CSV output file path |
| `--report <path>` | `iot_density_map.html`| Standalone HTML report path |
| `--gui-port <port>`| `8765` | Dashboard HTTP interface port |
| `--listen-all` | *False* | Binds dashboard to all network interfaces (Requires `--secure-privacy` and an integrity key) |
| `--secure-privacy` | *False* | Mask middle MAC octets (`AA:BB:XX:XX:XX:FF`) before saving |
| `--interval <sec>` | `3.0` | Scanning loop window interval timing |
| `--max-log-size-mb`| `10.0` | Maximum CSV file size before triggering rotation |
| `--max-archives` | `5` | Quantity of numbered CSV backup files to preserve |
| `--webhook-url` | *None* | Optional target HTTPS webhook to publish JSON batches |
| `--self-test` | *False* | Runs internal regression smoke tests and exits |

### Production Network Binding

To safely expose the live dashboard to your local network (`--listen-all`), you must mask hardware addresses and establish a hash verification key:

```bash
export BLE_INTEGRITY_KEY="your_secure_secret_key"
python ble_inventory.py --listen-all --secure-privacy
```

## Quality Self-Check

The script includes built-in quality control checks covering log rotation rules, queue throttling, network streaming parsing, and privacy filters:

```bash
python ble_inventory.py --self-test
```

## License

Distributed under the MIT License. See `LICENSE` for details.
