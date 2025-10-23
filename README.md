# Chainlink Node Setup

Automated installation script for running a Chainlink node on Ubuntu/Debian systems. Builds Chainlink from source and configures it to connect to Ethereum mainnet via a remote RPC endpoint.

## Files

- `setup.sh` - Main installation script (requires `.env` file)
- `config.toml` - Chainlink node configuration
- `secrets.toml` - Database credentials and keystore password
- `.env` - Environment variables for the setup script (not included)

## What It Does

The `setup.sh` script performs a complete installation:

1. **System Dependencies**: curl, wget, git, build-essential, PostgreSQL
2. **Development Tools**: Go (latest), Node.js LTS, pnpm, Rust, websocat
3. **Chainlink**: Clones and builds from [smartcontractkit/chainlink](https://github.com/smartcontractkit/chainlink) (latest release)
4. **Database**: Creates PostgreSQL database and user
5. **Service**: Creates systemd service running as dedicated `chainlink` user
6. **Reverse Proxy**: Configures Caddy with automatic HTTPS for `chainlink.brassey.io`
7. **Credentials**: Generates random admin password and saves to `~/chainlink_credentials.txt`

## Current Configuration

- **Ethereum Network**: Mainnet (ChainID 1)
- **RPC Endpoint**: `ethapi01.brassey.io` (HTTP + WebSocket)
- **Web UI**: Port 6688 (proxied via Caddy to `chainlink.brassey.io`)
- **Database**: PostgreSQL (`chainlink` user and database)

## Usage

1. Create `.env` file with required variables (see setup.sh for details)
2. Run the setup script:
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```
3. Access web UI at `http://localhost:6688` or `https://chainlink.brassey.io`
4. Login with credentials from `~/chainlink_credentials.txt`

## Reverse Proxy & TLS

The setup configures Caddy as a reverse proxy with automatic TLS termination:

- **Local Access**: `http://localhost:6688` (direct to Chainlink)
- **External Access**: `https://chainlink.brassey.io` (via Caddy)
- **TLS Certificates**: Automatic Let's Encrypt certificates (managed by Caddy)
- **Security Headers**: HSTS, X-Frame-Options, X-Content-Type-Options
- **Logs**: `/var/log/caddy/chainlink.log`

Caddy configuration (`/etc/caddy/Caddyfile`):
```
chainlink.brassey.io {
    reverse_proxy localhost:6688
    tls admin@brassey.io
}
```

**Requirements for HTTPS**:
- DNS A record: `chainlink.brassey.io` → your server IP
- Open ports: 80 (HTTP challenge), 443 (HTTPS)
- Valid email for Let's Encrypt notifications

## Configuration

Edit `config.toml` to change node settings:
- Web server port, CORS, TLS
- Ethereum RPC endpoints
- Chain ID

Edit `secrets.toml` for sensitive data:
- PostgreSQL connection string
- Keystore password

## Service Management

```bash
sudo systemctl status chainlink    # Check status
sudo systemctl start chainlink     # Start service
sudo systemctl stop chainlink      # Stop service
sudo systemctl restart chainlink   # Restart service
sudo journalctl -u chainlink -f    # View logs
```

## Requirements

- Ubuntu/Debian system with sudo access
- Internet connectivity
- DNS configured for `chainlink.brassey.io` (for Caddy HTTPS)
- Valid Ethereum RPC endpoint

## Notes

- Script is idempotent where possible (checks existing installations)
- Builds Chainlink from source (takes several minutes)
- Database password is URL-encoded in `secrets.toml` (%2F = /, %3D = =)
- Admin credentials are randomly generated on each run
- Service runs as unprivileged `chainlink` user with restricted permissions
