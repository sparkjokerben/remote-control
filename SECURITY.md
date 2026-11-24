# Security Policy

## Reporting a vulnerability

Please report security issues privately via GitHub's **Security → Report a vulnerability** on this repository, or email the maintainers listed in `package.json`. Do not open a public issue for an unpatched vulnerability.

## Scope

The plugin handles E2EE keys and remote session data. Reports about key handling, TOFU approval, replay protection, or the WebUI tunnel are especially welcome. Credentials and private keys never leave the host; the relay only forwards ciphertext for session remote control.
