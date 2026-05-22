"""
config.py - Centralized configuration loader for RAdmin.
Reads radmin.conf and exposes typed settings to server and client.
"""

import configparser
import os
import sys

CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'radmin.conf')


def load_config():
    if not os.path.exists(CONFIG_FILE):
        print(f"[ERROR] Configuration file not found: {CONFIG_FILE}")
        print("        Copy radmin.conf.example to radmin.conf and fill in your values.")
        sys.exit(1)

    cfg = configparser.ConfigParser()
    cfg.read(CONFIG_FILE)

    # Validate that placeholder values haven't been left in place
    shared_secret = cfg.get('credentials', 'shared_secret')
    if shared_secret == 'CHANGEME_GENERATE_WITH_SECRETS_MODULE':
        print("[ERROR] shared_secret in radmin.conf has not been set.")
        print("        Run: python -c \"import secrets; print(secrets.token_hex(32))\"")
        print("        and paste the result into radmin.conf under [credentials].")
        sys.exit(1)

    password = cfg.get('credentials', 'password')
    if password == 'CHANGEME':
        print("[ERROR] password in radmin.conf has not been set.")
        sys.exit(1)

    return cfg


# Single config instance imported by server and client
CONFIG = load_config()
