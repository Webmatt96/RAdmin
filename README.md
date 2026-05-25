# RAdmin Socket Service

A hardened, cross-platform remote administration socket service. Provides the client/server communication layer for the [RAdmin web platform](https://github.com/Webmatt96/radmin-web).

## Overview

RAdmin Socket Service is a Python-based client/server architecture that allows administrators to execute commands on remote machines over an encrypted, authenticated connection. It runs as a standalone service and communicates with the RAdmin Django web platform via Redis.

The server maintains persistent TLS connections from managed clients and dispatches commands on behalf of authenticated users. Clients run as background agents on each managed machine and reconnect automatically if the connection is lost.

## Security

- **TLS 1.2+** on all socket communication — no plaintext traffic
- **HMAC-SHA256 challenge/response** authentication — clients without the correct shared secret are rejected before any data exchange
- **Certificate pinning** on the client side — prevents man-in-the-middle attacks
- **Credentials in config file** — never in source code
- **Input validation** on all host file entries — prevents shell injection

## Architecture

```
RAdmin Web Platform (radmin-web)
        │
        │ Redis pub/sub
        │
RAdmin Socket Server ──── TLS/HMAC ──── Windows Client Agent
                     ──── TLS/HMAC ──── Linux Client Agent
                     ──── TLS/HMAC ──── [additional clients]
```

The socket server is a peer process to the Django web server. Django dispatches commands through Redis; the socket server receives them and forwards to the appropriate client.

## Requirements

- Python 3.11+
- OpenSSL (for certificate generation)
- Redis (shared with radmin-web)

No third-party Python packages required — all modules are from the standard library.

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/Webmatt96/RAdmin.git
cd RAdmin
```

### 2. Copy and configure

```bash
cp radmin.conf.example radmin.conf
```

Edit `radmin.conf` with your values. The file is gitignored and will never be committed.

### 3. Generate a shared secret

Both the server and every client must have the same value:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Paste the output into `radmin.conf` under `[credentials] shared_secret`.

### 4. Generate a TLS certificate (server only)

```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \
    -days 365 -nodes -subj "/CN=RAdmin Server"
```

Copy `server.crt` (not `server.key`) to each client machine.

### 5. Run the server

```bash
sudo python3 server_main.py
```

### 6. Run a client

On each managed machine:

```bash
sudo python3 client_main.py
```

## Available Commands

| Command | Description | Platform |
|---|---|---|
| `help` | List available commands | All |
| `sys_info` | OS, hostname, uptime, Python version | All |
| `cpu_usage` | Current CPU utilization | All |
| `memory_usage` | RAM usage summary | All |
| `disk_usage` | Filesystem usage | All |
| `service_list` | Running services | All |
| `service_status <name>` | Status of a specific service | All |
| `service_start <name>` | Start a service | All |
| `service_stop <name>` | Stop a service | All |
| `tail_syslog [lines]` | Last N lines of system log | All |
| `tail_applog [lines]` | Last N lines of application log | All |
| `net_connections` | Active network connections | All |
| `net_interfaces` | Network interface information | All |
| `reboot` | Reboot the machine | All |
| `application_log` | Windows Application Event Log | Windows |
| `installroot_log` | DoD PKE InstallRoot log | Windows |
| `failover_cluster_validation` | Run Test-Cluster | Windows |

## Client Behavior

- Connects to the server on startup and registers its hostname
- Reconnects automatically on disconnect using exponential backoff (5s → 10s → 20s → up to 5 minutes)
- Runs periodic connectivity checks against entries in the hosts file
- Executes commands in background threads so long-running commands don't block the connection

## File Reference

| File | Description |
|---|---|
| `server_main.py` | Headless CLI server — accepts client connections, dispatches commands |
| `client_main.py` | Client agent — runs on each managed machine |
| `commands.py` | Cross-platform command implementations |
| `config.py` | Configuration loader — reads `radmin.conf` |
| `radmin.conf.example` | Example configuration — copy to `radmin.conf` and fill in values |
| `SETUP.md` | Detailed setup and security guide |

## Related

- [radmin-web](https://github.com/Webmatt96/radmin-web) — Django web platform, CAC authentication, audit logging, ticketing integration, and credential management

## License

Internal use. All rights reserved.
