"""
commands.py - Command definitions executed on the client (managed) machine.
Cross-platform: detects OS and runs the appropriate implementation.
Credentials are loaded from radmin.conf, never hardcoded here.
"""

import os
import sys
import logging
import time
import subprocess
import re
import platform
from config import CONFIG

log_level = getattr(logging, CONFIG.get('client', 'log_level').upper(), logging.DEBUG)
logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')

IS_WINDOWS = platform.system() == 'Windows'


def get_available_commands():
    return [
        'help',
        'math',
        'sys_info',
        'cpu_usage',
        'memory_usage',
        'disk_usage',
        'service_list',
        'service_status <service_name>',
        'service_start <service_name>',
        'service_stop <service_name>',
        'tail_syslog [lines]',
        'tail_applog [lines]',
        'net_connections',
        'net_interfaces',
        'application_log',
        'installroot_log',
        'reboot',
        'failover_cluster_validation',
    ]


def help():
    lines = ['Available commands:', '']
    for cmd in get_available_commands():
        lines.append(f'  {cmd}')
    lines += [
        '',
        'Commands with <arg> require an argument:',
        '  service_status ssh',
        '  service_start nginx',
        '  tail_syslog 100',
    ]
    return '\n'.join(lines)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _run(args, shell=False):
    """Run a subprocess and return stdout+stderr as a string."""
    try:
        return subprocess.check_output(
            args, stderr=subprocess.STDOUT, text=True, shell=shell
        )
    except subprocess.CalledProcessError as e:
        return e.output or f"Command failed with exit code {e.returncode}"
    except FileNotFoundError as e:
        return f"Command not found: {e}"


def _run_ps(script):
    """Run a PowerShell script and return output."""
    return _run(['powershell', '-NoProfile', '-NonInteractive', '-Command', script])


# ── System Info ───────────────────────────────────────────────────────────────

def sys_info():
    """Return OS, hostname, uptime, and Python version."""
    import socket
    info = [
        f"Hostname   : {socket.gethostname()}",
        f"OS         : {platform.system()} {platform.release()}",
        f"Version    : {platform.version()}",
        f"Architecture: {platform.machine()}",
        f"Processor  : {platform.processor()}",
        f"Python     : {sys.version}",
    ]
    if IS_WINDOWS:
        uptime = _run_ps("(Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime | Select-Object -ExpandProperty TotalHours")
        info.append(f"Uptime (hrs): {uptime.strip()}")
    else:
        uptime = _run(['uptime', '-p'])
        info.append(f"Uptime     : {uptime.strip()}")
    return '\n'.join(info)


def cpu_usage():
    """Return current CPU usage."""
    if IS_WINDOWS:
        return _run_ps("Get-CimInstance Win32_Processor | Select-Object Name, LoadPercentage | Format-List")
    else:
        top = _run(['top', '-bn1'])
        for line in top.splitlines():
            if 'Cpu(s)' in line or '%Cpu' in line:
                return f"CPU: {line.strip()}"
        return top[:500]


def memory_usage():
    """Return memory usage summary."""
    if IS_WINDOWS:
        return _run_ps(
            "Get-CimInstance Win32_OperatingSystem | "
            "Select-Object @{N='Total(MB)';E={[math]::Round($_.TotalVisibleMemorySize/1KB,1)}}, "
            "@{N='Free(MB)';E={[math]::Round($_.FreePhysicalMemory/1KB,1)}}, "
            "@{N='Used(MB)';E={[math]::Round(($_.TotalVisibleMemorySize-$_.FreePhysicalMemory)/1KB,1)}} "
            "| Format-List"
        )
    else:
        return _run(['free', '-h'])


def disk_usage():
    """Return disk usage for all mounted filesystems."""
    if IS_WINDOWS:
        return _run_ps(
            "Get-PSDrive -PSProvider FileSystem | "
            "Select-Object Name, @{N='Used(GB)';E={[math]::Round($_.Used/1GB,2)}}, "
            "@{N='Free(GB)';E={[math]::Round($_.Free/1GB,2)}} | Format-Table -AutoSize"
        )
    else:
        return _run(['df', '-h'])


# ── Service Management ────────────────────────────────────────────────────────

def service_list():
    """List all running services."""
    if IS_WINDOWS:
        return _run_ps("Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, DisplayName | Format-Table -AutoSize")
    else:
        return _run(['systemctl', 'list-units', '--type=service', '--state=running', '--no-pager'])


def service_status(service_name=None):
    """Return status of a specific service."""
    if not service_name:
        return "Usage: service_status <service_name>"
    if IS_WINDOWS:
        return _run_ps(f"Get-Service -Name '{service_name}' | Format-List *")
    else:
        return _run(['systemctl', 'status', service_name, '--no-pager'])


def service_start(service_name=None):
    """Start a service."""
    if not service_name:
        return "Usage: service_start <service_name>"
    if IS_WINDOWS:
        return _run_ps(f"Start-Service -Name '{service_name}'")
    else:
        return _run(['sudo', 'systemctl', 'start', service_name])


def service_stop(service_name=None):
    """Stop a service."""
    if not service_name:
        return "Usage: service_stop <service_name>"
    if IS_WINDOWS:
        return _run_ps(f"Stop-Service -Name '{service_name}'")
    else:
        return _run(['sudo', 'systemctl', 'stop', service_name])


# ── Log Tailing ───────────────────────────────────────────────────────────────

def tail_syslog(lines=50):
    """Return the last N lines of the system log."""
    if IS_WINDOWS:
        return _run_ps(f"Get-EventLog -LogName System -Newest {lines} | Format-List TimeGenerated, EntryType, Source, Message")
    else:
        log_paths = ['/var/log/syslog', '/var/log/messages']
        for path in log_paths:
            if os.path.exists(path):
                return _run(['tail', f'-n{lines}', path])
        # Fallback to journalctl
        return _run(['journalctl', '-n', str(lines), '--no-pager'])


def tail_applog(lines=50):
    """Return the last N lines of the application log."""
    if IS_WINDOWS:
        return _run_ps(f"Get-EventLog -LogName Application -Newest {lines} | Format-List TimeGenerated, EntryType, Source, Message")
    else:
        log_paths = ['/var/log/auth.log', '/var/log/secure']
        for path in log_paths:
            if os.path.exists(path):
                return _run(['tail', f'-n{lines}', path])
        return _run(['journalctl', '-n', str(lines), '--no-pager', '-u', 'ssh'])


# ── Network Info ──────────────────────────────────────────────────────────────

def net_connections():
    """Return active network connections."""
    if IS_WINDOWS:
        return _run_ps("Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Format-Table -AutoSize")
    else:
        result = _run(['ss', '-tnp'])
        if 'not found' in result.lower():
            result = _run(['netstat', '-tnp'])
        return result


def net_interfaces():
    """Return network interface statistics."""
    if IS_WINDOWS:
        return _run_ps("Get-NetAdapter | Select-Object Name, Status, LinkSpeed, MacAddress | Format-Table -AutoSize")
    else:
        return _run(['ip', 'addr', 'show'])


# ── Hosts file / connectivity ─────────────────────────────────────────────────

def print_hosts_file():
    if IS_WINDOWS:
        hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
    else:
        hosts_path = '/etc/hosts'

    ip_addresses = []
    try:
        if IS_WINDOWS:
            # Read raw bytes and detect encoding — Windows hosts file may be
            # UTF-16 with BOM, UTF-16 without BOM, or plain ASCII/UTF-8
            with open(hosts_path, 'rb') as f:
                raw = f.read()
            if raw.startswith(b'\xff\xfe') or raw.startswith(b'\xfe\xff'):
                # UTF-16 with BOM
                content = raw.decode('utf-16')
            elif b'\x00' in raw:
                # UTF-16 without BOM — assume little-endian
                content = raw.decode('utf-16-le')
            else:
                # Plain ASCII or UTF-8
                content = raw.decode('utf-8', errors='replace')
            lines = content.splitlines()
        else:
            with open(hosts_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

        for line in lines:
            cleaned = line.strip()
            if not cleaned.startswith('#') and cleaned:
                parts = cleaned.split()
                if len(parts) >= 2:
                    ip_addresses.append(parts[0])
    except Exception as e:
        logging.error(f'Error reading hosts file: {e}')
    return ip_addresses


def _is_safe_ip(value):
    """
    Only allow valid IPv4, IPv6, or dotted hostnames.
    Rejects single-word hostnames like 'dhcp', 'lmhosts', 'pnceptmapper'.
    """
    # IPv4: four dotted octets
    ipv4 = re.match(r'^(\d{1,3}\.){3}\d{1,3}$', value)
    # IPv6: contains colons
    ipv6 = re.match(r'^[0-9a-fA-F:]+$', value) and ':' in value
    # Dotted hostname (e.g. host.domain.local) — must have at least one dot
    dotted = re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$', value)
    return bool(ipv4 or ipv6 or dotted)


def test_connectivity(ip_addresses):
    results = []
    for ip in ip_addresses:
        if not _is_safe_ip(ip):
            logging.warning(f'Skipping suspicious IP value: {ip!r}')
            continue
        try:
            args = ['ping', '-n', '1', '-w', '1000', ip] if IS_WINDOWS else ['ping', '-c', '1', '-W', '1', ip]
            result = subprocess.run(args, capture_output=True, timeout=5)
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
                encoded = message.encode('utf-8')
                header  = len(encoded).to_bytes(4, byteorder='big')
                client_socket.sendall(header + encoded)
            except OSError as e:
                logging.error(f'Error sending connectivity results: {e}')
        time.sleep(interval)


# ── Windows-specific ──────────────────────────────────────────────────────────

def application_log():
    if IS_WINDOWS:
        return _run_ps('Get-EventLog -LogName Application -Newest 10')
    return "application_log is Windows-only. Use tail_applog on Linux."


def installroot_log():
    if IS_WINDOWS:
        return _run_ps('Get-EventLog -LogName "DoD-PKE InstallRoot" -Newest 10')
    return "installroot_log is Windows-only."


def reboot():
    if IS_WINDOWS:
        return _run_ps('Restart-Computer -Force')
    else:
        return _run(['sudo', 'shutdown', '-r', 'now'])


def failover_cluster_validation():
    if not IS_WINDOWS:
        return "failover_cluster_validation is Windows-only."
    account  = CONFIG.get('credentials', 'account')
    password = CONFIG.get('credentials', 'password')
    ps_script = (
        f"$securePassword = ConvertTo-SecureString -String '{password}' -AsPlainText -Force; "
        f"$credential = New-Object System.Management.Automation.PSCredential ('{account}', $securePassword); "
        f"Test-Cluster -Credential $credential"
    )
    return _run_ps(ps_script)


# ── Misc ──────────────────────────────────────────────────────────────────────

def math():
    return str(2 + 2 * 6)
