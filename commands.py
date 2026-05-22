"""
commands.py - Command definitions executed on the client (managed) machine.
Credentials are loaded from radmin.conf, never hardcoded here.
"""

import os
import logging
import time
import subprocess
import re
from config import CONFIG

log_level = getattr(logging, CONFIG.get('client', 'log_level').upper(), logging.DEBUG)
logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')


def get_available_commands():
    return ['application_log', 'installroot_log', 'reboot', 'failover_cluster_validation', 'math']


def print_hosts_file():
    hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
    ip_addresses = []
    try:
        with open(hosts_path, 'r', encoding='utf-16') as file:
            for line in file:
                cleaned_line = line.replace('\x00', '').strip()
                if not cleaned_line.startswith('#') and cleaned_line:
                    parts = cleaned_line.split()
                    if len(parts) >= 2:
                        ip_addresses.append(parts[0])
    except Exception as e:
        logging.error(f'Error reading hosts file: {e}')
    return ip_addresses


def _is_safe_ip(value):
    """Reject anything that isn't a plain IPv4/IPv6 address or hostname."""
    return bool(re.match(r'^[a-zA-Z0-9.\-:]+$', value))


def test_connectivity(ip_addresses):
    """Ping each IP. Uses subprocess with argument list to prevent shell injection."""
    results = []
    for ip in ip_addresses:
        if not _is_safe_ip(ip):
            logging.warning(f'Skipping suspicious IP value: {ip!r}')
            continue
        try:
            result = subprocess.run(
                ['ping', '-n', '1', '-w', '1000', ip],
                capture_output=True,
                timeout=5
            )
            status = 'Reachable' if result.returncode == 0 else 'Unreachable'
            results.append((ip, status))
        except subprocess.TimeoutExpired:
            results.append((ip, 'Timeout'))
        except Exception as e:
            logging.error(f'Error pinging {ip}: {e}')
    return results


def periodic_connectivity_check(client_socket, interval):
    while True:
        ip_addresses = print_hosts_file()
        if ip_addresses:
            connectivity_results = test_connectivity(ip_addresses)
            lines = '\n'.join(f'{ip} is {status}' for ip, status in connectivity_results)
            message = f'CONNECTIVITY_RESULTS_START\n{lines}\nCONNECTIVITY_RESULTS_END'
            try:
                client_socket.send(message.encode())
            except OSError as e:
                logging.error(f'Error sending connectivity results: {e}')
        time.sleep(interval)


def application_log():
    return subprocess.check_output(
        ['powershell', '-NoProfile', '-NonInteractive', '-Command',
         'Get-EventLog -LogName Application -Newest 10'],
        stderr=subprocess.STDOUT, text=True
    )


def installroot_log():
    return subprocess.check_output(
        ['powershell', '-NoProfile', '-NonInteractive', '-Command',
         'Get-EventLog -LogName "DoD-PKE InstallRoot" -Newest 10'],
        stderr=subprocess.STDOUT, text=True
    )


def reboot():
    return subprocess.check_output(
        ['powershell', '-NoProfile', '-NonInteractive', '-Command',
         'Restart-Computer -Force'],
        stderr=subprocess.STDOUT, text=True
    )


def failover_cluster_validation():
    """
    Runs Test-Cluster using credentials from radmin.conf.
    The password is never embedded in source code.
    """
    account = CONFIG.get('credentials', 'account')
    password = CONFIG.get('credentials', 'password')

    ps_script = (
        f"$securePassword = ConvertTo-SecureString -String '{password}' "
        f"-AsPlainText -Force; "
        f"$credential = New-Object System.Management.Automation.PSCredential "
        f"('{account}', $securePassword); "
        f"Test-Cluster -Credential $credential"
    )
    return subprocess.check_output(
        ['powershell', '-NoProfile', '-NonInteractive', '-Command', ps_script],
        stderr=subprocess.STDOUT, text=True
    )


def math():
    return str(2 + 2 * 6)
