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
    help,
    test_connectivity,
    print_hosts_file,
    periodic_connectivity_check,
    sys_info,
    cpu_usage,
    memory_usage,
    disk_usage,
    service_list,
    service_status,
    service_start,
    service_stop,
    tail_syslog,
    tail_applog,
    net_connections,
    net_interfaces,
    application_log,
    installroot_log,
    reboot,
    failover_cluster_validation,
    math,
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
RECONNECT_WAIT = 5


# ── Command dispatch ──────────────────────────────────────────────────────────
# Commands that accept an optional argument are mapped to their function.
# The dispatcher splits the command string on the first space and passes
# the remainder as the argument.

COMMAND_MAP = {
    'help':                        lambda arg: help(),
    'math':                        lambda arg: math(),
    'sys_info':                    lambda arg: sys_info(),
    'cpu_usage':                   lambda arg: cpu_usage(),
    'memory_usage':                lambda arg: memory_usage(),
    'disk_usage':                  lambda arg: disk_usage(),
    'service_list':                lambda arg: service_list(),
    'service_status':              lambda arg: service_status(arg),
    'service_start':               lambda arg: service_start(arg),
    'service_stop':                lambda arg: service_stop(arg),
    'tail_syslog':                 lambda arg: tail_syslog(int(arg) if arg else 50),
    'tail_applog':                 lambda arg: tail_applog(int(arg) if arg else 50),
    'net_connections':             lambda arg: net_connections(),
    'net_interfaces':              lambda arg: net_interfaces(),
    'application_log':             lambda arg: application_log(),
    'installroot_log':             lambda arg: installroot_log(),
    'reboot':                      lambda arg: reboot(),
    'failover_cluster_validation': lambda arg: failover_cluster_validation(),
}


def execute_command(command_str):
    """
    Parse command string, dispatch to the right function.
    Format: '<command>' or '<command> <argument>'
    """
    parts     = command_str.strip().split(' ', 1)
    command   = parts[0].lower()
    argument  = parts[1].strip() if len(parts) > 1 else None

    func = COMMAND_MAP.get(command)
    if func:
        logging.debug(f"Executing: {command} | arg: {argument}")
        try:
            return func(argument)
        except Exception as e:
            return f'Error executing {command}: {e}'
    return f'Command "{command}" not recognized. Available: {", ".join(get_available_commands())}'


def send_message(conn, text):
    """
    Send a length-prefixed message.
    Format: 4-byte big-endian length header followed by UTF-8 payload.
    """
    encoded = text.encode('utf-8')
    header  = len(encoded).to_bytes(4, byteorder='big')
    conn.sendall(header + encoded)


def recv_message(conn):
    """
    Receive a complete length-prefixed message.
    Blocks until all bytes have arrived.
    Returns the decoded string, or None if the connection closed.
    """
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


def handle_command(conn, command):
    if not command:
        return
    result = execute_command(command)
    payload = f'RESULT_START\n{result}\nRESULT_END'
    try:
        send_message(conn, payload)
    except OSError as e:
        logging.error(f"Error sending result: {e}")


# ── Keep-alive ────────────────────────────────────────────────────────────────

def send_keep_alive(conn):
    while True:
        try:
            if conn.fileno() == -1:
                break
            send_message(conn, 'KEEP_ALIVE')
            time.sleep(30)
        except OSError as e:
            logging.error(f"Keep-alive error: {e}")
            break


# ── Authentication ────────────────────────────────────────────────────────────

def authenticate(conn):
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
            logging.error(f"Authentication rejected: {verdict}")
            return False
    except Exception as e:
        logging.error(f"Authentication error: {e}")
        return False


# ── TLS context ───────────────────────────────────────────────────────────────

def build_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    cert_file = CONFIG.get('server', 'cert_file', fallback=None)
    if cert_file and os.path.exists(cert_file):
        ctx.load_verify_locations(cert_file)
        ctx.verify_mode = ssl.CERT_REQUIRED
        logging.info(f"TLS: pinning to {cert_file}")
    else:
        ctx.load_default_certs()
        logging.warning("TLS: no pinned cert found, using system CA store")
    return ctx


# ── Backoff ───────────────────────────────────────────────────────────────────

BACKOFF_BASE   = 5    # seconds - initial wait
BACKOFF_MAX    = 300  # seconds - maximum wait (5 minutes)
BACKOFF_FACTOR = 2    # multiply delay by this on each failure


def backoff_wait(attempt):
    """
    Exponential backoff with a cap.
    attempt 0 ->   5s
    attempt 1 ->  10s
    attempt 2 ->  20s
    attempt 3 ->  40s
    attempt 4 ->  80s
    attempt 5 -> 160s
    attempt 6 -> 300s (capped)
    """
    delay = min(BACKOFF_BASE * (BACKOFF_FACTOR ** attempt), BACKOFF_MAX)
    logging.info(f"Reconnecting in {delay:.0f}s (attempt {attempt + 1})...")
    time.sleep(delay)


# ── Main loop ─────────────────────────────────────────────────────────────────

def start_client():
    host     = CONFIG.get('server', 'host')
    port     = CONFIG.getint('server', 'port')
    interval = CONFIG.getint('client', 'connectivity_check_interval')
    ssl_ctx  = build_ssl_context()

    attempt = 0  # reset to 0 on a successful connection

    while True:
        try:
            logging.info(f"Connecting to {host}:{port}")
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn = ssl_ctx.wrap_socket(raw_sock, server_hostname='RAdmin Server')
            conn.connect((host, port))
            conn.settimeout(300)
            logging.info("TLS connection established")

            if not authenticate(conn):
                logging.error("Authentication failed")
                conn.close()
                backoff_wait(attempt)
                attempt += 1
                continue

            # Successful connection — reset backoff
            attempt = 0
            logging.info("Connected and authenticated. Backoff reset.")

            hostname = socket.gethostname()
            send_message(conn, f'HOSTNAME:{hostname}')

            threading.Thread(target=send_keep_alive, args=(conn,), daemon=True).start()
            threading.Thread(
                target=periodic_connectivity_check,
                args=(conn, interval),
                daemon=True
            ).start()

            while True:
                try:
                    command = recv_message(conn)
                    if command is None:
                        logging.warning("Server disconnected (empty recv)")
                        break
                    command = command.strip()
                    logging.debug(f"Received: {command}")
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

        except Exception as e:
            logging.error(f"Connection error: {e}")

        backoff_wait(attempt)
        attempt += 1


if __name__ == '__main__':
    start_client()
