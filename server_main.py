"""
server_main.py - RAdmin Server (headless CLI version)
Accepts TLS-wrapped connections from authenticated clients.
Authentication uses a shared secret (HMAC challenge/response).
Credentials and settings are loaded from radmin.conf, never hardcoded.

Usage:
    python3 server_main.py                  # interactive mode
    python3 server_main.py --list           # list connected clients
"""

import socket
import ssl
import threading
import subprocess
import logging
import hmac
import hashlib
import secrets
import sys
import os
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

# ── Shared state ──────────────────────────────────────────────────────────────
clients      = {}   # hostname -> ssl_socket
clients_lock = threading.Lock()


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
    """Send a length-prefixed message."""
    encoded = text.encode('utf-8')
    header  = len(encoded).to_bytes(4, byteorder='big')
    conn.sendall(header + encoded)


def recv_message(conn):
    """Receive a complete length-prefixed message. Returns None on disconnect."""
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
                with clients_lock:
                    clients[hostname] = conn
                logging.info(f"Client registered: {hostname}")
                print(f"\n[+] Client connected: {hostname}")
                print_prompt()
            elif 'RESULT_START' in data and 'RESULT_END' in data:
                result = data.split('RESULT_START')[1].split('RESULT_END')[0].strip()
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
        conn = clients.get(hostname)
    if not conn:
        print(f"Client '{hostname}' not found. Use 'list' to see connected clients.")
        return
    try:
        send_message(conn, command)
        logging.info(f"Sent '{command}' to {hostname}")
        print(f"Command '{command}' sent to {hostname}. Waiting for result...")
    except OSError as e:
        print(f"Error sending command: {e}")


def cli_loop():
    print("\nRAdmin Server - Interactive Mode")
    print("Type 'list' to see connected clients, 'quit' to exit.")
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
                print(f"Available commands: {', '.join(get_available_commands())}")
            else:
                _, hostname, command = parts
                send_command(hostname, command)
        else:
            print(f"Unknown command: '{line}'")
            print(f"Available commands: {', '.join(get_available_commands())}")

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

    t = threading.Thread(target=accept_clients, args=(raw_sock, ssl_context), daemon=True)
    t.start()

    cli_loop()
