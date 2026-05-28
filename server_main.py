"""
server_main.py - RAdmin Server (headless CLI version)
Accepts TLS-wrapped connections from authenticated clients.
Authentication uses a shared secret (HMAC challenge/response).
Credentials and settings are loaded from radmin.conf, never hardcoded.

Redis bridge:
  - Subscribes to radmin:cmd:<hostname> for commands from the web UI
  - Publishes results to radmin:result:<hostname>:<request_id>
  - Publishes host online/offline events to radmin:host:status
"""

import socket
import ssl
import threading
import subprocess
import logging
import hmac
import hashlib
import secrets
import json
import sys
import os
import time
from config import CONFIG
from commands import get_available_commands

# ── Logging ───────────────────────────────────────────────────────────────────
log_level = getattr(logging, CONFIG.get('server', 'log_level', fallback='DEBUG').upper(), logging.DEBUG)
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('server_log.txt'),
        logging.StreamHandler(sys.stdout)
    ]
)

# ── Constants ─────────────────────────────────────────────────────────────────
SHARED_SECRET  = CONFIG.get('credentials', 'shared_secret').encode()
CHALLENGE_SIZE = 32
KEEP_ALIVE_SEC = 60
AUTH_TIMEOUT   = 10
RESULT_TTL     = 60   # seconds results stay in Redis

# ── Redis ─────────────────────────────────────────────────────────────────────
try:
    import redis as redis_lib
    REDIS_URL = CONFIG.get('infrastructure', 'redis_url', fallback='redis://localhost:6379/0')
    redis_client = redis_lib.from_url(REDIS_URL, decode_responses=True)
    redis_client.ping()
    REDIS_AVAILABLE = True
    logging.info(f"Redis connected: {REDIS_URL}")
except Exception as e:
    REDIS_AVAILABLE = False
    redis_client = None
    logging.warning(f"Redis not available: {e} — web UI bridge disabled")

# ── Shared state ──────────────────────────────────────────────────────────────
clients      = {}   # hostname -> {'conn': ssl_socket, 'lock': threading.Lock()}
clients_lock = threading.Lock()

# Pending results from clients: hostname -> threading.Event + result
pending      = {}
pending_lock = threading.Lock()


# ── Redis helpers ─────────────────────────────────────────────────────────────

def redis_publish_status(hostname, online):
    """Notify Django that a host came online or went offline."""
    if not REDIS_AVAILABLE:
        return
    try:
        redis_client.publish('radmin:host:status', json.dumps({
            'hostname': hostname,
            'online':   online,
            'ts':       time.time(),
        }))
    except Exception as e:
        logging.error(f"Redis publish status error: {e}")


def redis_publish_result(hostname, request_id, result):
    """Publish a command result back to Django."""
    if not REDIS_AVAILABLE:
        return
    try:
        key = f'radmin:result:{hostname}:{request_id}'
        redis_client.setex(key, RESULT_TTL, result)
        logging.debug(f"Published result to {key}")
    except Exception as e:
        logging.error(f"Redis publish result error: {e}")


def redis_command_listener():
    """
    Subscribe to radmin:cmd:* channels.
    When Django dispatches a command for a host, forward it to the client.
    Message format: JSON { request_id, command, args }
    Reconnects automatically if the connection drops.
    """
    if not REDIS_AVAILABLE:
        logging.warning("Redis unavailable — command listener not started")
        return

    while True:
        try:
            # Create a dedicated connection with no socket timeout for pubsub
            r = redis_lib.from_url(REDIS_URL, decode_responses=True, socket_timeout=None)
            pubsub = r.pubsub()
            pubsub.psubscribe('radmin:cmd:*')
            logging.info("Redis command listener started — subscribed to radmin:cmd:*")

            for message in pubsub.listen():
                if message['type'] != 'pmessage':
                    continue

                channel = message['channel']           # e.g. radmin:cmd:radmin-server
                hostname = channel.split('radmin:cmd:')[1]

                try:
                    payload = json.loads(message['data'])
                    request_id = payload.get('request_id')
                    command    = payload.get('command', '')
                    args       = payload.get('args', '')
                    full_cmd   = f"{command} {args}".strip() if args else command
                except Exception as e:
                    logging.error(f"Bad command payload: {e}")
                    continue

                logging.info(f"Redis command received: {full_cmd} for {hostname}")

                with clients_lock:
                    client = clients.get(hostname)
                    all_clients = list(clients.keys())

                logging.info(f"Looking up '{hostname}', connected: {all_clients}, found: {client is not None}")

                if not client:
                    error = f"Host '{hostname}' is not connected."
                    logging.warning(error)
                    redis_publish_result(hostname, request_id, error)
                    continue

                conn      = client['conn']
                send_lock = client['lock']

                # Register a pending result slot keyed by hostname
                event = threading.Event()
                with pending_lock:
                    pending[hostname] = {'event': event, 'result': None}

                try:
                    with send_lock:
                        send_message(conn, full_cmd)
                    logging.info(f"Command sent to {hostname}, waiting for result...")
                except Exception as e:
                    error = f"Failed to send command to {hostname}: {e}"
                    logging.error(error)
                    redis_publish_result(hostname, request_id, error)
                    with pending_lock:
                        pending.pop(hostname, None)
                    continue

                # Wait for the client to respond (up to 55s)
                logging.info(f"Waiting for result from {hostname}...")
                event.wait(timeout=55)
                logging.info(f"Wait complete for {hostname}, event set: {event.is_set()}")

                with pending_lock:
                    slot = pending.pop(hostname, None)

                result = slot['result'] if slot and slot['result'] else 'Timeout — no response from client.'
                logging.info(f"Publishing result for {hostname}: {result[:50]}")
                redis_publish_result(hostname, request_id, result)

        except Exception as e:
            logging.error(f"Redis command listener error: {e} — reconnecting in 5s")
            time.sleep(5)


# ── Authentication ────────────────────────────────────────────────────────────

def authenticate_client(conn):
    conn.settimeout(AUTH_TIMEOUT)
    try:
        challenge = secrets.token_bytes(CHALLENGE_SIZE)
        conn.sendall(challenge)
        response = conn.recv(64)
        if not response:
            return False
        expected = hmac.new(SHARED_SECRET, challenge, hashlib.sha256).hexdigest().encode()
        if hmac.compare_digest(response, expected):
            conn.sendall(b'AUTH_OK')
            return True
        else:
            conn.sendall(b'AUTH_FAIL')
            logging.warning("Client failed authentication (bad secret)")
            return False
    except Exception as e:
        logging.error(f"Authentication error: {e}")
        return False
    finally:
        conn.settimeout(KEEP_ALIVE_SEC)


# ── Message framing ───────────────────────────────────────────────────────────

def send_message(conn, text):
    encoded = text.encode('utf-8')
    header  = len(encoded).to_bytes(4, byteorder='big')
    conn.sendall(header + encoded)


def recv_message(conn):
    header = b''
    while len(header) < 4:
        chunk = conn.recv(4 - len(header))
        if not chunk:
            return None
        header += chunk

    length = int.from_bytes(header, byteorder='big')

    payload = b''
    while len(payload) < length:
        chunk = conn.recv(min(4096, length - len(payload)))
        if not chunk:
            return None
        payload += chunk

    return payload.decode('utf-8')


# ── Client handler ────────────────────────────────────────────────────────────

def handle_client(conn, addr):
    logging.info(f"New connection from {addr}, authenticating...")

    if not authenticate_client(conn):
        logging.warning(f"Rejected unauthenticated client from {addr}")
        conn.close()
        return

    logging.info(f"Client from {addr} authenticated successfully")
    hostname = None

    while True:
        try:
            data = recv_message(conn)
            if data is None:
                break
            data = data.strip()
            if not data:
                continue
            if data == 'KEEP_ALIVE':
                conn.settimeout(KEEP_ALIVE_SEC)
                continue
            if data.startswith('HOSTNAME:'):
                hostname = data.split('HOSTNAME:', 1)[1].strip()
                send_lock = threading.Lock()
                with clients_lock:
                    clients[hostname] = {'conn': conn, 'lock': send_lock}
                logging.info(f"Client registered: {hostname}")
                print(f"\n[+] Client connected: {hostname}")
                print_prompt()
                redis_publish_status(hostname, True)

            elif 'RESULT_START' in data and 'RESULT_END' in data:
                result = data.split('RESULT_START')[1].split('RESULT_END')[0].strip()
                logging.debug(f"Result received from {hostname}, pending slots: {list(pending.keys())}")

                # Resolve pending slot keyed by hostname
                resolved = False
                with pending_lock:
                    slot = pending.get(hostname)
                    if slot and not slot['event'].is_set():
                        slot['result'] = result
                        slot['event'].set()
                        resolved = True
                        logging.debug(f"Resolved pending request for {hostname}")

                if not resolved:
                    print(f"\n--- Result from {hostname} ---")
                    print(result)
                    print("--- End Result ---")
                    print_prompt()

            elif 'CONNECTIVITY_RESULTS_START' in data and 'CONNECTIVITY_RESULTS_END' in data:
                result = data.split('CONNECTIVITY_RESULTS_START')[1].split('CONNECTIVITY_RESULTS_END')[0].strip()
                print(f"\n--- Connectivity from {hostname} ---")
                print(result)
                print("--- End Connectivity ---")
                print_prompt()
            else:
                result = execute_server_command(data)
                send_message(conn, result)
        except Exception as e:
            logging.error(f"Error with client {hostname or addr}: {e}")
            break

    conn.close()
    if hostname:
        with clients_lock:
            clients.pop(hostname, None)
        logging.info(f"Client disconnected: {hostname}")
        print(f"\n[-] Client disconnected: {hostname}")
        print_prompt()
        redis_publish_status(hostname, False)


# ── Server-side command execution ─────────────────────────────────────────────

def execute_server_command(command):
    command_map = dict(CONFIG.items('commands'))
    ps_command = command_map.get(command.lower())
    if ps_command:
        try:
            return subprocess.check_output(
                ['powershell', '-NoProfile', '-NonInteractive', '-Command', ps_command],
                stderr=subprocess.STDOUT, text=True
            )
        except Exception as e:
            return f"Error: {e}"
    return f'Command "{command}" not recognized.'


# ── CLI interface ─────────────────────────────────────────────────────────────

def print_prompt():
    print("\nCommands: list | send <hostname> <command> | quit")
    print("> ", end='', flush=True)


def list_clients():
    with clients_lock:
        if not clients:
            print("No clients connected.")
        else:
            print("\nConnected clients:")
            for i, hostname in enumerate(clients.keys(), 1):
                print(f"  {i}. {hostname}")


def send_command(hostname, command):
    with clients_lock:
        client = clients.get(hostname)
    if not client:
        print(f"Client '{hostname}' not found.")
        return
    try:
        with client['lock']:
            send_message(client['conn'], command)
        logging.info(f"Sent '{command}' to {hostname}")
        print(f"Command '{command}' sent to {hostname}. Waiting for result...")
    except OSError as e:
        print(f"Error sending command: {e}")


def cli_loop():
    print("\nRAdmin Server - Interactive Mode")
    print("Type 'list' to see connected clients, 'quit' to exit.")
    if REDIS_AVAILABLE:
        print("[Redis bridge active — web UI commands enabled]")
    else:
        print("[Redis not available — web UI bridge disabled]")
    print_prompt()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            print_prompt()
            continue

        if line == 'quit':
            print("Shutting down.")
            os._exit(0)
        elif line == 'list':
            list_clients()
        elif line.startswith('send '):
            parts = line.split(' ', 2)
            if len(parts) < 3:
                print("Usage: send <hostname> <command>")
            else:
                _, hostname, command = parts
                send_command(hostname, command)
        else:
            print(f"Unknown command: '{line}'")

        print_prompt()


# ── Accept loop ───────────────────────────────────────────────────────────────

def accept_clients(server_socket, ssl_context):
    while True:
        try:
            raw_conn, addr = server_socket.accept()
            try:
                tls_conn = ssl_context.wrap_socket(raw_conn, server_side=True)
            except ssl.SSLError as e:
                logging.warning(f"TLS handshake failed from {addr}: {e}")
                raw_conn.close()
                continue
            t = threading.Thread(target=handle_client, args=(tls_conn, addr), daemon=True)
            t.start()
        except Exception as e:
            logging.error(f"Accept error: {e}")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    cert = CONFIG.get('server', 'cert_file')
    key  = CONFIG.get('server', 'key_file')
    port = CONFIG.getint('server', 'port')

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile=cert, keyfile=key)
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_sock.bind(('0.0.0.0', port))
    raw_sock.listen(270)
    logging.info(f"Server listening on 0.0.0.0:{port} with TLS")
    print(f"[*] RAdmin Server listening on port {port}")

    # Start Redis command listener in background
    t_redis = threading.Thread(target=redis_command_listener, daemon=True)
    t_redis.start()

    t = threading.Thread(target=accept_clients, args=(raw_sock, ssl_context), daemon=True)
    t.start()

    cli_loop()
