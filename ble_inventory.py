#!/usr/bin/env python3
"""Passive, consent-based BLE advertisement inventory.

Records nearby Bluetooth LE advertisements for authorized troubleshooting. This
utility does not connect to devices, transmit, correlate randomized addresses,
or infer movement. If Bleak is missing, the program attempts to install it using
its active interpreter's pip module.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import datetime as dt
from collections import deque
import html
import json
import hashlib
import hmac
import logging
import os
import http.server
import queue as thread_queue
import re
import socketserver
import threading
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from pathlib import Path
from typing import Any

LOG = logging.getLogger("ble_inventory")
FIELDS = ("timestamp_utc", "address", "rssi_dbm", "local_name", "service_uuids", "vendor", "distance", "integrity_digest")
OUI_VENDORS = {
    "4C:56:CC": "Apple", "00:23:3A": "Samsung", "D8:E0:E1": "Sony",
    "3C:5A:B4": "Google", "90:59:AF": "Fitbit", "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi", "3C:6A:A7": "Intel",
    "00:1B:21": "Intel", "64:09:80": "Xiaomi", "28:6C:07": "Xiaomi",
    "00:1B:54": "Cisco", "50:C7:BF": "TP-Link", "20:0C:C8": "Netgear",
    "00:17:88": "Philips", "24:0A:C4": "Espressif", "7C:DF:A1": "Espressif",
    "00:1D:63": "Bosch",
}


class LiveHub:
    """Bounded per-client event queues; scanner callbacks never perform socket I/O."""
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._clients: set[thread_queue.Queue[str]] = set()

    def subscribe(self) -> thread_queue.Queue[str]:
        client: thread_queue.Queue[str] = thread_queue.Queue(maxsize=128)
        with self._lock:
            self._clients.add(client)
        return client

    def unsubscribe(self, client: thread_queue.Queue[str]) -> None:
        with self._lock:
            self._clients.discard(client)

    def publish(self, data: dict[str, Any]) -> None:
        payload = json.dumps(data, separators=(",", ":"))
        with self._lock:
            clients = tuple(self._clients)
        for client in clients:
            try:
                client.put_nowait(payload)
            except thread_queue.Full:
                try:
                    client.get_nowait()
                except thread_queue.Empty:
                    pass
                try:
                    client.put_nowait(payload)
                except thread_queue.Full:
                    pass


LIVE_HUB = LiveHub()


def describe_rssi(value: Any) -> str:
    try:
        rssi = int(value)
    except (TypeError, ValueError):
        return "Unknown"
    if rssi >= -52:
        return "Immediate (<1 Meter)"
    if rssi >= -70:
        return "Nearby (Same Room)"
    if rssi >= -86:
        return "Distant (Within Range)"
    return "Very Distant (Edge of Range)"


def normalize_address(address: str) -> str:
    """Normalize colon, hyphen, dotted, and abbreviated six-octet MAC text."""
    text = str(address).strip()
    if re.fullmatch(r"[0-9A-Fa-f]{12}", text):
        octets = [text[i:i + 2] for i in range(0, 12, 2)]
    else:
        octets = [part for part in re.split(r"[^0-9A-Fa-f]+", text) if part]
    if len(octets) != 6 or any(not 1 <= len(part) <= 2 for part in octets):
        return text.upper()
    try:
        return ":".join(f"{int(part, 16):02X}" for part in octets)
    except ValueError:
        return text.upper()


def display_address(address: str, secure_privacy: bool) -> str:
    normalized = normalize_address(address)
    parts = normalized.split(":")
    if secure_privacy and len(parts) == 6:
        return ":".join((parts[0], parts[1], "XX", "XX", "XX", parts[5]))
    return normalized



def integrity_digest(record: dict[str, Any], key: str | None = None) -> str:
    """Return a canonical SHA-256 checksum or keyed HMAC-SHA-256 authenticity tag."""
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if key:
        return "hmac-sha256:" + hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, default=Path("iot_wardrive_log.csv"), help="CSV output path")
    parser.add_argument("--report", type=Path, default=Path("iot_density_map.html"), help="HTML report path")
    parser.add_argument("--gui-port", type=int, default=8765, help="Dashboard HTTP port")
    parser.add_argument("--listen-all", action="store_true", help="Bind dashboard to all interfaces; requires privacy masking and integrity key")
    parser.add_argument("--integrity-key", help="HMAC key; prefer BLE_INTEGRITY_KEY environment variable")
    parser.add_argument("--interval", type=float, default=3.0, help="Seconds per scan interval (default: 3)")
    parser.add_argument("--queue-size", type=int, default=4096, help="Maximum queued advertisements")
    parser.add_argument("--batch-size", type=int, default=128, help="Maximum records per disk flush batch")
    parser.add_argument("--max-log-size-mb", type=float, default=10.0, help="Rotate active CSV at this size")
    parser.add_argument("--max-archives", type=int, default=5, help="Number of numbered CSV archives to retain")
    parser.add_argument("--webhook-url", help="Optional HTTPS endpoint receiving each persisted batch as JSON")
    parser.add_argument("--webhook-token", help="Optional bearer token; prefer BLE_WEBHOOK_TOKEN environment variable")
    parser.add_argument("--secure-privacy", action="store_true", help="Mask address middle octets before storage/export")
    parser.add_argument("--self-test", action="store_true", help="Run built-in offline quality checks and exit")
    parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR"), default="INFO")
    args = parser.parse_args(argv)
    if args.interval <= 0 or args.queue_size <= 0 or args.batch_size <= 0:
        parser.error("--interval, --queue-size, and --batch-size must be greater than zero")
    if not 1 <= args.gui_port <= 65535:
        parser.error("--gui-port must be between 1 and 65535")
    if args.max_log_size_mb <= 0 or args.max_archives < 0:
        parser.error("--max-log-size-mb must be positive and --max-archives must be zero or greater")
    if args.webhook_url:
        parsed_webhook = urlsplit(args.webhook_url)
        if parsed_webhook.scheme.lower() != "https" or not parsed_webhook.hostname or parsed_webhook.username or parsed_webhook.password:
            parser.error("--webhook-url must be a valid HTTPS URL without embedded credentials; cleartext HTTP is rejected")
    if args.webhook_token is None:
        args.webhook_token = os.environ.get("BLE_WEBHOOK_TOKEN")
    if args.integrity_key is None:
        args.integrity_key = os.environ.get("BLE_INTEGRITY_KEY")
    if args.listen_all and not args.secure_privacy:
        parser.error("--listen-all requires --secure-privacy to mask address identifiers")
    if args.listen_all and not args.integrity_key:
        parser.error("--listen-all requires BLE_INTEGRITY_KEY or --integrity-key; use TLS via a trusted reverse proxy for transport encryption")
    return args


def start_dashboard(report_path: Path, port: int, listen_all: bool = False) -> tuple[socketserver.ThreadingTCPServer, threading.Thread]:
    """Serve on loopback by default; LAN binding is explicitly opt-in and HMAC-gated."""
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            LOG.debug("dashboard client=%s " + fmt, self.client_address[0], *args)

        def do_GET(self) -> None:
            if self.path == "/stream":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-cache, no-transform")
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                client = LIVE_HUB.subscribe()
                try:
                    self.wfile.write(b": connected\n\n")
                    self.wfile.flush()
                    while True:
                        try:
                            payload = client.get(timeout=15)
                            self.wfile.write(("data: " + payload + "\n\n").encode("utf-8"))
                        except thread_queue.Empty:
                            self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                finally:
                    LIVE_HUB.unsubscribe(client)
                return
            if self.path not in ("/", "/index.html"):
                self.send_error(404)
                return
            try:
                page = report_path.read_text(encoding="utf-8")
            except OSError:
                page = "<!doctype html><meta charset=utf-8><title>BLE monitor</title><h1>Waiting for observations</h1>"
            script = '''<div style="display:flex;gap:8px;flex-wrap:wrap;margin:12px 0"><button id="pauseLive" type="button">Pause live stream</button><input id="liveSearch" type="search" placeholder="Filter live rows" aria-label="Filter live rows"></div>
<script>
const source=new EventSource('/stream');let paused=false,pending=[];const body=document.querySelector('#data tbody');
function addObservation(d){if(!body)return;const row=document.createElement('tr');[d.timestamp_utc,d.address,d.rssi_dbm,d.local_name,d.service_uuids,d.vendor,d.distance,d.integrity_digest].forEach(v=>{const cell=document.createElement('td');cell.textContent=v??'';row.appendChild(cell)});body.prepend(row);while(body.children.length>1000)body.lastElementChild.remove();applySearch();}
source.onmessage=(event)=>{const d=JSON.parse(event.data);if(paused){pending.push(d);if(pending.length>1000)pending.shift();}else addObservation(d);};
document.getElementById('pauseLive').addEventListener('click',e=>{paused=!paused;e.currentTarget.textContent=paused?'Resume live stream':'Pause live stream';if(!paused){for(const item of pending)addObservation(item);pending=[];}});
document.getElementById('liveSearch').addEventListener('input',applySearch);
function applySearch(){const q=document.getElementById('liveSearch').value.toLowerCase();for(const row of body?.rows||[])row.hidden=!row.innerText.toLowerCase().includes(q);}
</script>'''
            page = page.replace("</html>", script + "</html>")
            body = page.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

    class ThreadedTCPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    bind_host = "0.0.0.0" if listen_all else "127.0.0.1"
    server = ThreadedTCPServer((bind_host, port), Handler)
    thread = threading.Thread(target=server.serve_forever, name="ble-dashboard-http", daemon=True)
    thread.start()
    LOG.info("dashboard listening on %s:%d; remote mode requires HTTPS reverse proxy", bind_host, server.server_address[1])
    return server, thread


def configure_logging(level: str) -> None:
    logging.basicConfig(level=getattr(logging, level),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s",
                        datefmt="%Y-%m-%dT%H:%M:%S%z")


def timestamp_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def ensure_csv(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() or path.stat().st_size == 0:
        with path.open("a", newline="", encoding="utf-8") as stream:
            csv.DictWriter(stream, fieldnames=FIELDS).writeheader()
            stream.flush()
            os.fsync(stream.fileno())


def rotate_log(path: Path, max_archives: int) -> None:
    """Rotate numbered archives newest-first and remove all stale excess files."""
    archive_pattern = re.compile(re.escape(path.name) + r"\.(\d+)$")
    existing: dict[int, Path] = {}
    for candidate in path.parent.iterdir():
        match = archive_pattern.fullmatch(candidate.name)
        if match and candidate.is_file():
            existing[int(match.group(1))] = candidate

    # Explicitly delete every numbered archive outside the configured retention cap.
    for number, archive in existing.items():
        if number > max_archives or max_archives == 0:
            archive.unlink()
    if max_archives == 0:
        if path.exists():
            path.unlink()
        return

    # Shift from highest retained index down. Missing indexes are harmless; every
    # archive that exists is moved exactly once, without truncating an older source.
    for index in range(max_archives - 1, 0, -1):
        source = Path(f"{path}.{index}")
        if source.exists():
            os.replace(source, Path(f"{path}.{index + 1}"))
    if path.exists():
        os.replace(path, Path(f"{path}.1"))


def append_batch(path: Path, batch: list[dict[str, Any]], max_size_bytes: int,
                 max_archives: int) -> None:
    """Size-check and rotate before each bounded durable append batch."""
    if not batch:
        return
    import io
    buffer = io.StringIO(newline="")
    csv.DictWriter(buffer, fieldnames=FIELDS, extrasaction="ignore").writerows(batch)
    encoded = buffer.getvalue().encode("utf-8")
    current_size = path.stat().st_size if path.exists() else 0
    if current_size and current_size + len(encoded) > max_size_bytes:
        rotate_log(path, max_archives)
    if not path.exists() or path.stat().st_size == 0:
        ensure_csv(path)
    with path.open("a", newline="", encoding="utf-8") as stream:
        stream.write(encoded.decode("utf-8"))
        stream.flush()
        os.fsync(stream.fileno())


def post_webhook(url: str | None, token: str | None, batch: list[dict[str, Any]]) -> None:
    """Send a persisted batch over HTTPS; network errors are isolated from capture."""
    if not url:
        return
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=json.dumps({"observations": batch}).encode("utf-8"),
                                     headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            if response.status < 200 or response.status >= 300:
                raise urllib.error.HTTPError(url, response.status, "non-success response", response.headers, None)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        LOG.warning("webhook delivery failed; local batch is durable; reason=%s", exc)


def distance_class(distance: str) -> str:
    if distance.startswith("Immediate"):
        return "badge green"
    if distance.startswith("Nearby"):
        return "badge yellow"
    if distance.startswith("Distant"):
        return "badge orange"
    if distance.startswith("Very Distant"):
        return "badge gray"
    return "badge"


def create_report(log_path: Path, report_path: Path) -> None:
    """Stream CSV rows into a compact, standalone HTML report."""
    counts: dict[str, int] = {}
    total = 0
    # Bounded rolling window: retain the newest 2,000 rendered rows while streaming CSV.
    preview_rows: deque[str] = deque(maxlen=1000)
    if log_path.exists():
        with log_path.open("r", newline="", encoding="utf-8") as source:
            for row in csv.DictReader(source):
                total += 1
                name = row.get("local_name") or "Unnamed BLE device"
                counts[name] = counts.get(name, 0) + 1
                cells = "".join(
                    f'<td><span class="{distance_class(row.get("distance", ""))}">{html.escape(row.get(key, ""))}</span></td>'
                    if key == "distance" else f"<td>{html.escape(row.get(key, ''))}</td>"
                    for key in FIELDS
                )
                preview_rows.append(f"<tr>{cells}</tr>")
    maximum = max(counts.values(), default=1)
    bars = "".join(
        f'<g><text x="8" y="{24 + i * 29}" font-size="12">{html.escape(name[:40])}</text>'
        f'<rect x="250" y="{9 + i * 29}" width="{max(2, int(480 * count / maximum))}" height="18" fill="#42d6aa"/>'
        f'<text x="{258 + int(480 * count / maximum)}" y="{24 + i * 29}" font-size="12">{count}</text></g>'
        for i, (name, count) in enumerate(sorted(counts.items(), key=lambda item: -item[1])[:30])
    )
    table_head = "".join(f"<th>{html.escape(name)}</th>" for name in FIELDS)
    document = f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>BLE Inventory Report</title><style>
*{{box-sizing:border-box}}body{{margin:0;background:#0b1220;color:#e7edf7;font:15px system-ui,sans-serif}}main{{max-width:1200px;margin:auto;padding:24px}}.muted{{color:#9aabc2}}.card{{background:#131e30;border:1px solid #26364e;border-radius:14px;padding:18px;margin:16px 0;overflow:auto}}.metric{{font-size:30px;color:#42d6aa}}table{{width:100%;border-collapse:collapse;min-width:720px}}th,td{{padding:9px;text-align:left;border-bottom:1px solid #26364e;overflow-wrap:anywhere}}th{{color:#42d6aa}}input{{padding:10px;width:min(100%,420px);background:#0b1220;color:white;border:1px solid #40536d;border-radius:8px}}svg{{max-width:100%;height:auto}}.radar{{width:16px;height:16px;border-radius:50%;background:#42d6aa;display:inline-block;box-shadow:0 0 0 0 #42d6aa88;animation:pulse 1.8s infinite}}@keyframes pulse{{to{{box-shadow:0 0 0 18px #42d6aa00}}}}.badge{{display:inline-block;padding:4px 8px;border-radius:99px}}.green{{background:#14532d;color:#bbf7d0}}.yellow{{background:#713f12;color:#fef08a}}.orange{{background:#7c2d12;color:#fed7aa}}.gray{{background:#374151;color:#d1d5db}}.notice{{border-left:4px solid #f0b44d;padding:10px 14px;background:#20283a}}
</style><main><h1>Bluetooth LE inventory</h1><p class="muted">Local passive-advertisement report · no device connection, address-rotation correlation, or movement inference.</p>
<section class="card"><span class="radar" aria-label="Live scan active"></span> <strong>Live monitor</strong><div class="metric">{total}</div> observations in active CSV</section><section class="card"><h2>Broadcast name counts</h2><svg viewBox="0 0 780 {max(70, min(930, 40 + len(counts) * 29))}" role="img" aria-label="Observation counts">{bars}</svg></section>
<section class="card"><h2>Live observations (newest 1,000)</h2><input id="q" placeholder="Search records" oninput="filterRows()"><table id="data"><thead><tr>{table_head}</tr></thead><tbody>{''.join(reversed(preview_rows))}</tbody></table></section>
<p class="notice">BLE addresses can be randomized and are not reliable personal identifiers. Use only for authorized troubleshooting.</p></main>
<script>function filterRows(){{const q=document.getElementById('q').value.toLowerCase();document.querySelectorAll('#data tbody tr').forEach(r=>r.hidden=!r.innerText.toLowerCase().includes(q))}}</script></html>'''
    report_path.parent.mkdir(parents=True, exist_ok=True)
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=report_path.parent,
                                         prefix=f".{report_path.name}.", suffix=".tmp", delete=False) as tmp:
            temp_name = tmp.name
            tmp.write(document)
            tmp.flush()
            os.fsync(tmp.fileno())
        os.replace(temp_name, report_path)
        temp_name = None
    finally:
        if temp_name is not None:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass


async def storage_consumer(queue: asyncio.Queue, log_path: Path, batch_size: int,
                           producer_done: asyncio.Event, max_size_bytes: int,
                           max_archives: int, webhook_url: str | None,
                           webhook_token: str | None, report_path: Path) -> None:
    """Consume records in bounded batches and durably append them off-loop."""
    batch: list[dict[str, Any]] = []
    while True:
        if producer_done.is_set() and queue.empty():
            break
        try:
            record = await asyncio.wait_for(queue.get(), timeout=0.25)
        except asyncio.TimeoutError:
            record = None
        if record is not None:
            batch.append(record)
            queue.task_done()
        if len(batch) >= batch_size or (batch and (record is None or (producer_done.is_set() and queue.empty()))):
            delivery_batch = list(batch)
            await asyncio.to_thread(append_batch, log_path, delivery_batch, max_size_bytes, max_archives)
            LOG.debug("durably wrote batch size=%d", len(delivery_batch))
            if webhook_url:
                await asyncio.to_thread(post_webhook, webhook_url, webhook_token, delivery_batch)
            await asyncio.to_thread(create_report, log_path, report_path)
            batch.clear()
    if batch:
        delivery_batch = list(batch)
        await asyncio.to_thread(append_batch, log_path, delivery_batch, max_size_bytes, max_archives)
        if webhook_url:
            await asyncio.to_thread(post_webhook, webhook_url, webhook_token, delivery_batch)
        await asyncio.to_thread(create_report, log_path, report_path)


async def run(args: argparse.Namespace) -> None:
    try:
        from bleak import BleakScanner
    except ImportError:
        LOG.warning("BLE scanner dependency 'bleak' is missing; attempting installation into the active Python environment")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "bleak"])
            from bleak import BleakScanner
        except (subprocess.CalledProcessError, OSError, ImportError) as exc:
            LOG.critical("Could not install or import bleak. Check network/proxy and permissions, then run: %s -m pip install bleak", sys.executable)
            raise SystemExit(2) from exc

    ensure_csv(args.log)
    dashboard_server, dashboard_thread = start_dashboard(args.report, args.gui_port, args.listen_all)
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=args.queue_size)
    stop_event = asyncio.Event()
    producer_done = asyncio.Event()
    dropped = 0

    def request_stop(signum: int) -> None:
        LOG.info("shutdown requested signal=%s", signal.Signals(signum).name)
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, request_stop, sig)
        except (NotImplementedError, RuntimeError):
            signal.signal(sig, lambda signum, _frame: loop.call_soon_threadsafe(request_stop, signum))

    def on_advertisement(device: Any, advertisement: Any) -> None:
        nonlocal dropped
        raw_address = str(getattr(device, "address", ""))
        normalized_address = normalize_address(raw_address)
        rssi = getattr(advertisement, "rssi", "")
        oui = ":".join(normalized_address.split(":")[:3]) if len(normalized_address.split(":")) == 6 else ""
        data = {
            "timestamp_utc": timestamp_utc(),
            "address": display_address(normalized_address, args.secure_privacy),
            "rssi_dbm": rssi,
            "local_name": getattr(advertisement, "local_name", None) or getattr(device, "name", None) or "",
            "service_uuids": ";".join(sorted(set(getattr(advertisement, "service_uuids", None) or []))),
            "vendor": OUI_VENDORS.get(oui, "Unknown manufacturer"),
            "distance": describe_rssi(rssi),
        }
        data["integrity_digest"] = integrity_digest(data, args.integrity_key)
        def enqueue() -> None:
            nonlocal dropped
            try:
                queue.put_nowait(data)
                LIVE_HUB.publish(data)
            except asyncio.QueueFull:
                dropped += 1
        loop.call_soon_threadsafe(enqueue)

    consumer = asyncio.create_task(
        storage_consumer(queue, args.log, args.batch_size, producer_done,
                         int(args.max_log_size_mb * 1024 * 1024), args.max_archives,
                         args.webhook_url, args.webhook_token, args.report),
        name="csv-storage-consumer")
    scanner: Any = None
    backoff = 1.0
    try:
        scanner = BleakScanner(detection_callback=on_advertisement)
        while not stop_event.is_set():
            started = time.monotonic()
            try:
                await scanner.start()
                backoff = 1.0
                remaining = max(0.0, args.interval - (time.monotonic() - started))
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=remaining)
                except asyncio.TimeoutError:
                    pass
                await scanner.stop()
                # Target intervals are start-to-start, without accumulating scan-time drift.
                elapsed = time.monotonic() - started
                if not stop_event.is_set() and elapsed < args.interval:
                    try:
                        await asyncio.wait_for(stop_event.wait(), timeout=args.interval - elapsed)
                    except asyncio.TimeoutError:
                        pass
            except asyncio.CancelledError:
                raise
            except Exception:
                LOG.exception("BLE adapter scan failed; retrying after %.1f seconds", backoff)
                try:
                    await scanner.stop()
                except Exception:
                    LOG.debug("scanner stop after adapter failure also failed", exc_info=True)
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=backoff)
                except asyncio.TimeoutError:
                    pass
                backoff = min(backoff * 2, 60.0)
    finally:
        if scanner is not None:
            try:
                await scanner.stop()
            except Exception:
                LOG.debug("scanner shutdown reported an error", exc_info=True)
        producer_done.set()
        await queue.join()
        await consumer
        if dropped:
            LOG.warning("queue capacity reached; dropped advertisements=%d", dropped)
        await asyncio.to_thread(create_report, args.log, args.report)
        LOG.info("report written path=%s", args.report.resolve())
        dashboard_server.shutdown()
        dashboard_server.server_close()
        dashboard_thread.join(timeout=2)


def run_quality_checks() -> None:
    """Offline smoke/regression checks for core boundaries and lifecycle helpers."""
    assert normalize_address("AA-BB-CC-DD-EE-FF") == "AA:BB:CC:DD:EE:FF"
    assert normalize_address("A:B:C:D:E:F") == "0A:0B:0C:0D:0E:0F"
    assert display_address("AA:BB:CC:DD:EE:FF", True) == "AA:BB:XX:XX:XX:FF"
    assert display_address("AA:BB:CC:DD:EE:FF", False) == "AA:BB:CC:DD:EE:FF"
    assert [describe_rssi(v) for v in (-52, -53, -70, -71, -86, -87)] == [
        "Immediate (<1 Meter)", "Nearby (Same Room)", "Nearby (Same Room)",
        "Distant (Within Range)", "Distant (Within Range)", "Very Distant (Edge of Range)",
    ]
    assert OUI_VENDORS.get("4C:56:CC") == "Apple"
    payload = {"timestamp_utc": "test", "address": "masked"}
    digest = integrity_digest(payload, "test-secret")
    assert digest.startswith("hmac-sha256:") and digest == integrity_digest(payload, "test-secret")
    assert digest != integrity_digest({**payload, "address": "changed"}, "test-secret")
    hub = LiveHub()
    subscriber = hub.subscribe()
    hub.publish({"probe": "event"})
    assert json.loads(subscriber.get_nowait())["probe"] == "event"
    hub.unsubscribe(subscriber)

    with tempfile.TemporaryDirectory(prefix="ble-inventory-check-") as directory:
        root = Path(directory)
        log_path = root / "observations.csv"
        report_path = root / "report.html"
        ensure_csv(log_path)
        # Sparse archive indexes and stale archives must preserve all in-cap files
        # while explicitly purging numbered archives beyond the retention limit.
        gap_log = root / "gap.csv"
        gap_log.write_text("active", encoding="utf-8")
        Path(f"{gap_log}.1").write_text("newest-archive", encoding="utf-8")
        Path(f"{gap_log}.3").write_text("older-archive", encoding="utf-8")
        Path(f"{gap_log}.9").write_text("stale", encoding="utf-8")
        rotate_log(gap_log, 3)
        assert Path(f"{gap_log}.1").read_text() == "active"
        assert Path(f"{gap_log}.2").read_text() == "newest-archive"
        assert Path(f"{gap_log}.3").read_text() == "older-archive"
        assert not Path(f"{gap_log}.9").exists()
        sample_rows = [
            {"timestamp_utc": str(i), "address": "AA:BB:XX:XX:XX:FF", "rssi_dbm": -52,
             "local_name": f"row-{i}", "service_uuids": "", "vendor": "Apple",
             "distance": describe_rssi(-52)}
            for i in range(1005)
        ]
        append_batch(log_path, sample_rows, 10_000_000, 2)
        with log_path.open("r", newline="", encoding="utf-8") as stream:
            assert sum(1 for _ in csv.DictReader(stream)) == 1005
        create_report(log_path, report_path)
        page = report_path.read_text(encoding="utf-8")
        assert "row-1004" in page and "row-5" in page and "<td>row-4</td>" not in page
        table_body = page.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
        assert table_body.index("row-1004") < table_body.index("row-5")
        assert "EventSource" not in page  # SSE client bootstrap is added by HTTP handler.
        dashboard, dashboard_thread = start_dashboard(report_path, 0)
        try:
            dashboard_url = f"http://127.0.0.1:{dashboard.server_address[1]}/"
            served_page = urllib.request.urlopen(dashboard_url, timeout=3).read().decode("utf-8")
            assert "EventSource('/stream')" in served_page
            assert "Pause live stream" in served_page and "liveSearch" in served_page
            assert "127.0.0.1" in dashboard_url
            with urllib.request.urlopen(dashboard_url + "stream", timeout=3) as stream_response:
                assert stream_response.readline() == b": connected\n"
                assert stream_response.readline() == b"\n"
                LIVE_HUB.publish({"probe": "sse-line-check"})
                assert b"sse-line-check" in stream_response.readline()
                assert stream_response.readline() == b"\n"
        finally:
            dashboard.shutdown()
            dashboard.server_close()
            dashboard_thread.join(timeout=2)
        for i in range(8):
            append_batch(log_path, [{**sample_rows[0], "timestamp_utc": f"rotate-{i}"}], 100, 2)
        assert not Path(f"{log_path}.3").exists()
        assert Path(f"{log_path}.1").exists() and Path(f"{log_path}.2").exists()
    LOG.info("quality checks passed: boundaries, privacy, SSE queue, CSV/report window, rotation retention")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    configure_logging(args.log_level)
    if args.self_test:
        try:
            run_quality_checks()
            return 0
        except Exception:
            LOG.exception("built-in quality checks failed")
            return 1
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        # Signal handlers normally route this through the coordinated shutdown path.
        LOG.info("interrupted")
    except SystemExit as exc:
        return int(exc.code or 0)
    except Exception:
        LOG.exception("service terminated unexpectedly")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
