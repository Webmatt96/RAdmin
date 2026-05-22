"""
client_main.py - RAdmin Client Agent
Runs on each managed machine. Connects to the server over TLS,
authenticates via HMAC challenge/response, then waits for commands.
"""

import socket
import ssl
import time
import logging
import threading
import hmac
import hashlib
import os
import sys
from config import CONFIG
from commands import (
    get_available_commands,
    test_connectivity,
    print_hosts_file,
    periodic_connectivity_check,
    application_log,
    installroot_log,
    reboot,
    failover_cluster_validation,
    math
)

# ── Logging ───────────────────────────────────────────────────────────────────
log_level = getattr(logging, CONFIG.get('client', 'log_level').upper(), logging.DEBUG)
logging.basicConfig(
    filename='client_log.txt',
    level=log_level,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ── Constants ─────────────────────────────────────────────────────────────────
SHARED_SECRET  = CONFIG.get('credentials', 'shared_secret').encode()
RECONNECT_WAIT = 5   # seconds between reconnect attempts


# ── Command dispatch ──────────────────────────────────────────────────────────

COMMAND_MAP = {
    'application_log':           application_log,
    'installroot_log':           installroot_log,
    'reboot':                    reboot,
    'failover_cluster_validation': failover_cluster_validation,
    'math':                      math,
}


def execute_command(command):
    func = COMMAND_MAP.get(command.lower())
    logging.debug(f"Executing command: {command}")
    if func:
        try:
            return func()
        except Exception as e:
            return f'Error executing {command}: {e}'
    return f'Command "{command}" not recognized.'


def handle_command(conn, command):
    if not command:
        return
    result = execute_command(command)
    payload = f'RESULT_START\n{result}\nRESULT_END'
    try:
        conn.sendall(payload.encode())
    except OSError as e:
        logging.error(f"Error sending result: {e}")


# ── Keep-alive ────────────────────────────────────────────────────────────────

def send_keep_alive(conn):
    while True:
        try:
            if conn.fileno() == -1:
                break
            conn.sendall(b'KEEP_ALIVE')
            time.sleep(30)
        except OSError as e:
            logging.error(f"Keep-alive error: {e}")
            break


# ── Authentication ────────────────────────────────────────────────────────────

def authenticate(conn):
    """
    Respond to the server's HMAC challenge.
    1. Receive challenge bytes from server.
    2. Compute HMAC-SHA256(shared_secret, challenge).
    3. Send the hex digest back.
    4. Wait for AUTH_OK or AUTH_FAIL.
    Returns True if server accepted us.
    """
    try:
        challenge = conn.recv(32)
        if not challenge or len(challenge) != 32:
            logging.error("Did not receive a valid challenge from server")
            return False

        response = hmac.new(SHARED_SECRET, challenge, hashlib.sha256).hexdigest().encode()
        conn.sendall(response)

        verdict = conn.recv(16).decode().strip()
        if verdict == 'AUTH_OK':
            logging.info("Authentication successful")
            return True
        else:
            logging.error(f"Authentication rejected by server: {verdict}")
            return False
    except Exception as e:
        logging.error(f"Authentication error: {e}")
        return False


# ── TLS context (client side) ─────────────────────────────────────────────────

def build_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    cert_file = CONFIG.get('server', 'cert_file', fallback=None)
    if cert_file and os.path.exists(cert_file):
        # Pin to the server's self-signed cert (recommended for internal tools)
        ctx.load_verify_locations(cert_file)
        ctx.verify_mode = ssl.CERT_REQUIRED
        logging.info(f"TLS: pinning to {cert_file}")
    else:
        # Fall back to system CA store if no pinned cert is available.
        # For production, always pin the cert.
        ctx.load_default_certs()
        logging.warning("TLS: no pinned cert found, using system CA store")

    return ctx


# ── Main loop ─────────────────────────────────────────────────────────────────

def start_client():
    host     = CONFIG.get('server', 'host')
    port     = CONFIG.getint('server', 'port')
    interval = CONFIG.getint('client', 'connectivity_check_interval')
    ssl_ctx  = build_ssl_context()

    while True:
        try:
            logging.info(f"Connecting to {host}:{port}")
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Wrap in TLS; server_hostname must match CN in the cert
            conn = ssl_ctx.wrap_socket(raw_sock, server_hostname='RAdmin Server')
            conn.connect((host, port))
            conn.settimeout(300)
            logging.info("TLS connection established")

            if not authenticate(conn):
                logging.error("Authentication failed, retrying in %ds", RECONNECT_WAIT)
                conn.close()
                time.sleep(RECONNECT_WAIT)
                continue

            # Identify ourselves to the server
            hostname = socket.gethostname()
            conn.sendall(f'HOSTNAME:{hostname}'.encode())

            # Background threads
            threading.Thread(target=send_keep_alive, args=(conn,), daemon=True).start()
            threading.Thread(
                target=periodic_connectivity_check,
                args=(conn, interval),
                daemon=True
            ).start()

            # Command receive loop
            while True:
                try:
                    command = conn.recv(1024).decode().strip()
                    logging.debug(f"Received command: {command}")
                    if command.lower() == 'exit':
                        break
                    if command:
                        threading.Thread(
                            target=handle_command,
                            args=(conn, command),
                            daemon=True
                        ).start()
                except socket.timeout:
                    logging.error("Socket timed out")
                    break
                except Exception as e:
                    logging.error(f"Receive error: {e}")
                    break

            conn.close()
            logging.info("Connection closed")

        except Exception as e:
            logging.error(f"Connection error: {e}")

        logging.info(f"Reconnecting in {RECONNECT_WAIT}s...")
        time.sleep(RECONNECT_WAIT)


if __name__ == '__main__':
    start_client()
