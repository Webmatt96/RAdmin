# RAdmin Security Setup Guide

## First-Time Setup (do this before running anything)

### 1. Rotate the xadmin password
The previous password was committed to the public repo in plaintext.
Rotate it in Active Directory before proceeding.

### 2. Copy the example config and fill it in
```
copy radmin.conf.example radmin.conf
```
Edit `radmin.conf` with your actual values. This file is in `.gitignore`
and must never be committed to git.

### 3. Generate a shared secret
Run this once and paste the output into `radmin.conf` under `[credentials] shared_secret`.
Both the server machine and every client machine must have the same value.

```
python -c "import secrets; print(secrets.token_hex(32))"
```

### 4. Generate a TLS certificate (server machine only)
```
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=RAdmin Server"
```
- `server.key` — private key, stays on the server only, never committed
- `server.crt` — certificate, copy this to each client machine

### 5. Distribute files to client machines
Each managed machine needs:
- `client_main.py`
- `commands.py`
- `config.py`
- `radmin.conf` (filled in with credentials and shared_secret)
- `server.crt` (the server's certificate, for TLS pinning)

The client does NOT need `server.key`.

---

## How Security Works

### TLS Encryption
All traffic between server and client is encrypted using TLS 1.2 minimum.
No commands, results, credentials, or hostnames travel in plaintext.

### HMAC Authentication (challenge/response)
When a client connects, the server sends 32 random bytes as a challenge.
The client computes HMAC-SHA256(shared_secret, challenge) and sends back
the hex digest. The server verifies using `hmac.compare_digest` (timing-safe).
A client without the correct shared_secret cannot connect — it will be
rejected before it can send any commands or identify itself.

### Certificate Pinning
The client is configured to verify the server's certificate against the
local copy of `server.crt`. This prevents man-in-the-middle attacks on
your internal network.

### No Credentials in Source Code
Credentials live only in `radmin.conf`, which is excluded from git via
`.gitignore`. The example file `radmin.conf.example` contains only
placeholder values and is safe to commit.

---

## What Is Still In Scope (future hardening)

- **Role-based access** — right now any authenticated client can run any
  command. A roles section in the config would let you restrict which
  machines can trigger a reboot vs. just read logs.
- **Web interface** — replacing the Tkinter server GUI with Flask + HTTPS
  would let you administer from a browser without needing the server GUI
  open. This is the next logical step.
- **Certificate rotation** — the self-signed cert expires in 365 days.
  Set a calendar reminder.
- **Startup as a service** — the client should run as a Windows service
  under the service account, not as a scheduled task. See Notes.txt.
