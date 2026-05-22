"""
server_main.py - RAdmin Server
Accepts TLS-wrapped connections from authenticated clients.
Authentication uses a shared secret (HMAC challenge/response).
Credentials and settings are loaded from radmin.conf, never hardcoded.
"""

import socket
import ssl
import threading
import subprocess
import logging
import hmac
import hashlib
import os
import secrets
import tkinter as tk
from config import CONFIG
from commands import get_available_commands

# ── Logging ──────────────────────────────────────────────────────────────────
log_level = getattr(logging, CONFIG.get('server', 'log_level', fallback='DEBUG').upper(), logging.DEBUG)
logging.basicConfig(
    filename='server_log.txt',
    level=log_level,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ── Constants ─────────────────────────────────────────────────────────────────
SHARED_SECRET   = CONFIG.get('credentials', 'shared_secret').encode()
CHALLENGE_SIZE  = 32          # bytes of random challenge sent to each client
KEEP_ALIVE_SEC  = 60
AUTH_TIMEOUT    = 10          # seconds a client has to complete the handshake


class ServerApp:
    def __init__(self, master):
        self.master = master
        self.master.title("NFSA Remote Admin")
        self.master.geometry('800x800')

        # ── UI ────────────────────────────────────────────────────────────────
        tk.Label(master, text='Connected Clients:').pack()
        self.client_listbox = tk.Listbox(master, selectmode=tk.BROWSE)
        self.client_listbox.pack(fill=tk.BOTH, expand=True)
        self.client_listbox.bind('<<ListboxSelect>>', self.on_client_select)

        tk.Label(master, text='Select Command:').pack()
        self.command_listbox = tk.Listbox(master, selectmode=tk.BROWSE)
        self.command_listbox.pack(fill=tk.BOTH, expand=True)
        self.command_listbox.bind('<<ListboxSelect>>', self.on_command_select)

        tk.Button(master, text='Send Command', command=self.send_command).pack(
            fill=tk.BOTH, expand=True, padx=10, pady=5)

        tk.Label(master, text='Command Output:').pack()
        self.result_text = tk.Text(master, height=10)
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        tk.Label(master, text='Connectivity Status:').pack()
        self.connectivity_text = tk.Text(master, height=5)
        self.connectivity_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # ── State ─────────────────────────────────────────────────────────────
        self.clients      = {}          # hostname -> ssl_socket
        self.clients_lock = threading.Lock()
        self.selected_client  = None
        self.selected_command = None

        # Populate command list
        for cmd in get_available_commands():
            self.command_listbox.insert(tk.END, cmd)

        # ── TLS context (server side) ─────────────────────────────────────────
        cert = CONFIG.get('server', 'cert_file')
        key  = CONFIG.get('server', 'key_file')
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.load_cert_chain(certfile=cert, keyfile=key)
        # Only allow TLS 1.2 and above
        self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

        # ── Socket ───────────────────────────────────────────────────────────
        port = CONFIG.getint('server', 'port')
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_sock.bind(('0.0.0.0', port))
        raw_sock.listen(270)
        self.server_socket = raw_sock
        logging.info(f"Server listening on port {port} with TLS")

        # ── Accept thread ─────────────────────────────────────────────────────
        t = threading.Thread(target=self.accept_clients, daemon=True)
        t.start()

    # ── Connection handling ───────────────────────────────────────────────────

    def accept_clients(self):
        while True:
            try:
                raw_conn, addr = self.server_socket.accept()
                # Wrap in TLS before doing anything else
                try:
                    tls_conn = self.ssl_context.wrap_socket(raw_conn, server_side=True)
                except ssl.SSLError as e:
                    logging.warning(f"TLS handshake failed from {addr}: {e}")
                    raw_conn.close()
                    continue

                t = threading.Thread(
                    target=self.handle_client,
                    args=(tls_conn, addr),
                    daemon=True
                )
                t.start()
            except Exception as e:
                logging.error(f"Error accepting connection: {e}")

    def authenticate_client(self, conn):
        """
        HMAC challenge/response handshake.
        1. Server sends a random challenge.
        2. Client replies with HMAC-SHA256(shared_secret, challenge).
        3. Server verifies using hmac.compare_digest (timing-safe).
        Returns True if authentication succeeds.
        """
        conn.settimeout(AUTH_TIMEOUT)
        try:
            challenge = secrets.token_bytes(CHALLENGE_SIZE)
            conn.sendall(challenge)

            response = conn.recv(64)  # 32-byte HMAC = 64 hex chars
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

    def handle_client(self, conn, addr):
        logging.info(f"New connection from {addr}, starting authentication")

        if not self.authenticate_client(conn):
            logging.warning(f"Rejected unauthenticated client from {addr}")
            conn.close()
            return

        logging.info(f"Client from {addr} authenticated successfully")
        hostname = None

        while True:
            try:
                data = conn.recv(4096).decode().strip()
                if not data:
                    continue
                if data == 'KEEP_ALIVE':
                    conn.settimeout(KEEP_ALIVE_SEC)
                    continue
                if data.startswith('HOSTNAME:'):
                    hostname = data.split('HOSTNAME:', 1)[1].strip()
                    with self.clients_lock:
                        self.clients[hostname] = conn
                    self.update_client_listbox()
                    logging.info(f"Registered client: {hostname}")
                elif 'RESULT_START' in data and 'RESULT_END' in data:
                    self._handle_result(data, hostname)
                else:
                    result = self.execute_command(data)
                    conn.sendall(result.encode())
            except Exception as e:
                logging.error(f"Error with client {hostname or addr}: {e}")
                break

        conn.close()
        if hostname:
            with self.clients_lock:
                self.clients.pop(hostname, None)
            self.update_client_listbox()
        logging.info(f"Client {hostname or addr} disconnected")

    def _handle_result(self, data, hostname):
        try:
            result = data.split('RESULT_START')[1].split('RESULT_END')[0].strip()
            if 'CONNECTIVITY_RESULTS_START' in data:
                self.master.after(0, self.connectivity_text.delete, '1.0', tk.END)
                self.master.after(0, self.connectivity_text.insert, tk.END,
                                  f'Connectivity from {hostname}:\n{result}\n')
            else:
                self.master.after(0, self.result_text.insert, tk.END,
                                  f'Result from {hostname}:\n{result}\n')
        except IndexError:
            logging.error(f"Malformed result from {hostname}: {data}")

    # ── Command execution (server-side PowerShell) ────────────────────────────

    def execute_command(self, command):
        command_map = dict(CONFIG.items('commands'))
        ps_command = command_map.get(command.lower())
        if ps_command:
            try:
                return subprocess.check_output(
                    ['powershell', '-NoProfile', '-NonInteractive', '-Command', ps_command],
                    stderr=subprocess.STDOUT, text=True
                )
            except subprocess.CalledProcessError as e:
                return e.output
        return f'Command "{command}" not recognized.'

    # ── UI callbacks ──────────────────────────────────────────────────────────

    def update_client_listbox(self):
        self.client_listbox.delete(0, tk.END)
        with self.clients_lock:
            for hostname in self.clients:
                self.client_listbox.insert(tk.END, hostname)

    def on_client_select(self, event):
        sel = self.client_listbox.curselection()
        if sel:
            self.selected_client = self.client_listbox.get(sel)

    def on_command_select(self, event):
        sel = self.command_listbox.curselection()
        if sel:
            self.selected_command = self.command_listbox.get(sel)

    def send_command(self):
        if not self.selected_client or not self.selected_command:
            logging.debug('No client or command selected')
            return
        with self.clients_lock:
            conn = self.clients.get(self.selected_client)
        if conn:
            try:
                conn.sendall(self.selected_command.encode())
                logging.info(f"Sent '{self.selected_command}' to {self.selected_client}")
            except OSError as e:
                logging.error(f"Failed to send command to {self.selected_client}: {e}")


if __name__ == '__main__':
    root = tk.Tk()
    app = ServerApp(root)
    root.mainloop()
