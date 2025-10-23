#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Store the original directory where the script is run from
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Dynamic version detection (populated during installation)
GO_VERSION=""
NODE_VERSION=""
PNPM_VERSION=""
POSTGRES_VERSION=""

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check network connectivity
check_network() {
    print_status "Checking network connectivity..."
    
    # Test basic connectivity
    if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        print_error "No internet connectivity detected. Please check your network connection."
        return 1
    fi
    
    print_success "Network connectivity verified"
}

# Function to check if TOML configuration files exist
check_config_files() {
    print_status "Script directory: $SCRIPT_DIR"
    print_status "Looking for config.toml and secrets.toml files..."
    
    if [[ ! -f "$SCRIPT_DIR/config.toml" ]]; then
        print_error "CRITICAL: config.toml file not found!"
        print_error "This script requires a config.toml file with Chainlink configuration."
        print_error "Please create a config.toml file in the script directory: $SCRIPT_DIR"
        exit 1
    fi
    
    if [[ ! -f "$SCRIPT_DIR/secrets.toml" ]]; then
        print_error "CRITICAL: secrets.toml file not found!"
        print_error "This script requires a secrets.toml file with Chainlink secrets."
        print_error "Please create a secrets.toml file in the script directory: $SCRIPT_DIR"
        exit 1
    fi
    
    print_success "Configuration files found and validated"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should not be run as root. Please run as a regular user with sudo privileges."
        exit 1
    fi
}

# Function to install system dependencies
install_system_dependencies() {
    print_status "Installing system dependencies..."
    
    # Update package lists
    sudo apt-get update
    
    # Install essential packages
    sudo apt-get install -y \
        curl \
        wget \
        git \
        build-essential \
        pkg-config \
        libssl-dev \
        libffi-dev \
        python3-dev \
        jq \
        postgresql \
        postgresql-contrib \
        postgresql-client \
        ca-certificates \
        gnupg \
        lsb-release \
        software-properties-common \
        unzip \
        make \
        gcc \
        g++ \
        libc6-dev
    
    print_success "System dependencies installed"
}

# Function to install websocat
install_websocat() {
    print_status "Installing websocat for WebSocket testing..."
    
    if command_exists websocat; then
        print_success "websocat is already installed"
        return
    fi
    
    # Install Rust if not available
    if ! command_exists cargo; then
        print_status "Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source ~/.cargo/env
        export PATH="$HOME/.cargo/bin:$PATH"
    fi
    
    # Install websocat using cargo
    if command_exists cargo; then
        print_status "Installing websocat via cargo..."
        cargo install websocat
        if command_exists websocat; then
            print_success "websocat installed successfully"
        else
            print_warning "Failed to install websocat - WebSocket testing will be skipped"
        fi
    else
        print_warning "cargo not available - WebSocket testing will be skipped"
    fi
}

# Function to get latest Go version
get_latest_go_version() {
    local latest_version
    # Use the correct API endpoint for Go versions
    latest_version=$(curl -s --connect-timeout 10 https://go.dev/dl/ | grep -o 'go[0-9]\+\.[0-9]\+\.[0-9]\+\.linux-amd64\.tar\.gz' | head -n1 | sed 's/\.linux-amd64\.tar\.gz//')
    
    if [[ -z "$latest_version" ]]; then
        # Fallback: try GitHub API
        latest_version=$(curl -s --connect-timeout 10 https://api.github.com/repos/golang/go/releases/latest | jq -r '.tag_name' 2>/dev/null)
        if [[ -z "$latest_version" || "$latest_version" == "null" ]]; then
            print_error "Failed to get latest Go version from go.dev and GitHub"
            return 1
        fi
    fi
    
    echo "${latest_version#go}"
}

# Function to install latest Go
install_go() {
    if command_exists go; then
        GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        print_success "Go $GO_VERSION is already installed"
        return
    fi
    
    # Get latest Go version
    GO_VERSION=$(get_latest_go_version)
    if [[ -z "$GO_VERSION" ]]; then
        print_error "Failed to get latest Go version"
        return 1
    fi
    
    print_status "Installing Go $GO_VERSION..."
    
    # Download and install latest Go
    cd $TEMP_DIR
    local go_tarball="go${GO_VERSION}.linux-amd64.tar.gz"
    
    # Only download if not already present
    if [[ ! -f "$go_tarball" ]]; then
        if ! wget "https://go.dev/dl/$go_tarball"; then
            print_error "Failed to download Go $GO_VERSION"
            return 1
        fi
    else
        print_status "Go tarball already exists, using cached version"
    fi
    
    # Remove existing Go installation
    sudo rm -rf /usr/local/go
    
    if ! sudo tar -C /usr/local -xzf "$go_tarball"; then
        print_error "Failed to extract Go $GO_VERSION"
        return 1
    fi
    
    # Clean up tarball only if we downloaded it
    if [[ -f "$go_tarball" ]]; then
        rm "$go_tarball"
    fi
    
    print_success "Go $GO_VERSION installed successfully"
}

# Function to setup Go environment
setup_go_environment() {
    print_status "Setting up Go environment..."
    
    # Add Go to PATH for current session
    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=$HOME/go
    export PATH=$GOPATH/bin:$PATH
    
    # Add Go to PATH for future sessions
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo 'export GOPATH=$HOME/go' >> ~/.bashrc
    echo 'export PATH=$GOPATH/bin:$PATH' >> ~/.bashrc
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
    echo 'export GOPATH=$HOME/go' >> ~/.profile
    echo 'export PATH=$GOPATH/bin:$PATH' >> ~/.profile
    
    # Verify Go is working
    if ! command_exists go; then
        print_error "Go installation failed - go command not found"
        return 1
    fi
    
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    print_success "Go $GO_VERSION environment configured"
}

# Function to install latest Node.js LTS and pnpm
install_nodejs() {
    if command_exists node; then
        NODE_VERSION=$(node --version | sed 's/v//')
        print_success "Node.js $NODE_VERSION is already installed"
    else
        print_status "Installing Node.js LTS..."
        # Install latest Node.js LTS using NodeSource repository
        curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
        sudo apt-get install -y nodejs
        NODE_VERSION=$(node --version | sed 's/v//')
        print_status "Installed Node.js $NODE_VERSION"
    fi
    
    # Update npm to latest version to avoid notices
    print_status "Updating npm to latest version..."
    sudo npm install -g npm@latest
    
    # Install latest pnpm (idempotent)
    if command_exists pnpm; then
        PNPM_VERSION=$(pnpm --version)
        print_success "pnpm $PNPM_VERSION is already installed"
    else
        print_status "Installing pnpm..."
        sudo npm install -g pnpm@latest
        PNPM_VERSION=$(pnpm --version)
        print_status "Installed pnpm $PNPM_VERSION"
    fi
    
    print_success "Node.js $NODE_VERSION and pnpm $PNPM_VERSION ready"
}

# Function to setup PostgreSQL
setup_postgresql() {
    print_status "Setting up PostgreSQL..."
    
    # Start and enable PostgreSQL
    sudo systemctl start postgresql
    sudo systemctl enable postgresql
    
    # Get actual PostgreSQL version after installation
    POSTGRES_VERSION=$(sudo -u postgres psql -c "SELECT version();" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -n1 || echo "Unknown")
    print_status "PostgreSQL $POSTGRES_VERSION is running"
    
    # Extract database password from secrets.toml and URL-decode it
    local db_password
    if [[ -f "$SCRIPT_DIR/secrets.toml" ]]; then
        db_password=$(grep -oP 'URL = .postgresql://[^:]+:\K([^@]+)' "$SCRIPT_DIR/secrets.toml" | sed "s/'//g")
        # URL decode the password (decode %2F to / and %3D to =)
        db_password=$(python3 -c "import urllib.parse; print(urllib.parse.unquote('$db_password'))")
    else
        print_error "secrets.toml not found - cannot extract database password"
        return 1
    fi
    
    # Create chainlink user and database (idempotent)
    sudo -u postgres psql << EOF
-- Create user if not exists (PostgreSQL 9.1+)
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '$CHAINLINK_DB_USER') THEN
        CREATE USER $CHAINLINK_DB_USER WITH PASSWORD '$db_password';
    ELSE
        ALTER USER $CHAINLINK_DB_USER WITH PASSWORD '$db_password';
    END IF;
END
\$\$;

-- Create database if not exists
SELECT 'CREATE DATABASE $CHAINLINK_DB_NAME OWNER $CHAINLINK_DB_USER'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$CHAINLINK_DB_NAME')\gexec

-- Grant privileges (idempotent)
GRANT ALL PRIVILEGES ON DATABASE $CHAINLINK_DB_NAME TO $CHAINLINK_DB_USER;
ALTER USER $CHAINLINK_DB_USER CREATEDB;
\q
EOF
    
    print_success "PostgreSQL $POSTGRES_VERSION configured for Chainlink"
}

# Function to create chainlink user and directories
setup_chainlink_user() {
    print_status "Creating chainlink user and directories..."
    
    # Create chainlink user (idempotent)
    if ! id "$CHAINLINK_USER" &>/dev/null; then
        sudo useradd -r -s /bin/bash -d /home/$CHAINLINK_USER $CHAINLINK_USER
        print_status "Created chainlink user"
    else
        print_status "Chainlink user already exists"
    fi
    
    # Create group if it doesn't exist
    if ! getent group $CHAINLINK_GROUP >/dev/null 2>&1; then
        sudo groupadd $CHAINLINK_GROUP
        print_status "Created chainlink group"
    fi
    
    # Add user to group (idempotent)
    sudo usermod -aG $CHAINLINK_GROUP $CHAINLINK_USER 2>/dev/null || true
    
    # Create directories (idempotent)
    sudo mkdir -p $CHAINLINK_HOME
    sudo mkdir -p $CHAINLINK_LOG_DIR
    sudo mkdir -p $CHAINLINK_HOME/.chainlink
    sudo mkdir -p /home/$CHAINLINK_USER
    sudo mkdir -p /home/$CHAINLINK_USER/.chainlink
    
    # Set ownership (always update to ensure correct permissions)
    sudo chown -R $CHAINLINK_USER:$CHAINLINK_GROUP $CHAINLINK_HOME
    sudo chown -R $CHAINLINK_USER:$CHAINLINK_GROUP $CHAINLINK_LOG_DIR
    sudo chown -R $CHAINLINK_USER:$CHAINLINK_GROUP /home/$CHAINLINK_USER
    sudo chmod 755 /home/$CHAINLINK_USER
    
    print_success "Chainlink user and directories ready"
}

# Function to get latest Chainlink version
get_latest_chainlink_version() {
    local version
    version=$(curl -s --connect-timeout 10 https://api.github.com/repos/smartcontractkit/chainlink/releases/latest | jq -r '.tag_name')
    if [[ -z "$version" || "$version" == "null" ]]; then
        print_error "Failed to get latest Chainlink version from GitHub"
        return 1
    fi
    echo "$version"
}

# Function to build Chainlink
build_chainlink() {
    # Check if Chainlink is already installed and up to date
    if command_exists chainlink; then
        local current_version
        current_version=$(chainlink version 2>/dev/null | head -n1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' || echo "")
        local latest_version
        latest_version=$(get_latest_chainlink_version)
        
        if [[ "$current_version" == "$latest_version" ]]; then
            print_success "Chainlink $current_version is already installed and up to date"
            return
        else
            print_status "Chainlink $current_version is installed, but $latest_version is available. Updating..."
        fi
    fi
    
    print_status "Cloning and building Chainlink..."
    
    # Get latest version
    local chainlink_version
    chainlink_version=$(get_latest_chainlink_version)
    print_status "Installing Chainlink $chainlink_version..."
    
    # Clone the repository (idempotent)
    cd $TEMP_DIR
    if [[ -d "chainlink" ]]; then
        print_status "Chainlink repository already exists, updating..."
        cd chainlink
        git fetch --all
        # Reset to the specific tag instead of main branch
        git reset --hard "$chainlink_version"
    else
        git clone https://github.com/smartcontractkit/chainlink.git
        cd chainlink
    fi
    
    # Checkout latest release
    git checkout "$chainlink_version"
    
    # Install Go tools required for Chainlink (with error handling)
    print_status "Installing Go Ethereum tools..."
    # Install only the tools that still exist in the latest go-ethereum
    go install github.com/ethereum/go-ethereum/cmd/abigen@latest || print_warning "Failed to install abigen"
    go install github.com/ethereum/go-ethereum/cmd/clef@latest || print_warning "Failed to install clef"
    go install github.com/ethereum/go-ethereum/cmd/ethkey@latest || print_warning "Failed to install ethkey"
    go install github.com/ethereum/go-ethereum/cmd/evm@latest || print_warning "Failed to install evm"
    go install github.com/ethereum/go-ethereum/cmd/geth@latest || print_warning "Failed to install geth"
    go install github.com/ethereum/go-ethereum/cmd/rlpdump@latest || print_warning "Failed to install rlpdump"
    go install github.com/ethereum/go-ethereum/cmd/devp2p@latest || print_warning "Failed to install devp2p"
    
    print_status "Note: Some Go Ethereum tools (bootnode, faucet, p2psim, utils) have been removed in the latest version"
    
    # Ensure Go is in PATH for the build
    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=$HOME/go
    export PATH=$GOPATH/bin:$PATH
    
    # Build Chainlink with error handling
    print_status "Running 'make generate'..."
    if ! make generate; then
        print_error "Failed to run 'make generate'"
        return 1
    fi
    
    print_status "Running 'make install'..."
    if ! make install; then
        print_error "Failed to run 'make install'"
        return 1
    fi
    
    # Verify binary was created
    if [[ ! -f "$GOPATH/bin/chainlink" ]]; then
        print_error "Chainlink binary was not created. Build failed."
        return 1
    fi
    
    # Stop Chainlink service if running to avoid "Text file busy" error
    if systemctl is-active --quiet $CHAINLINK_SERVICE_NAME 2>/dev/null; then
        print_status "Stopping Chainlink service to update binary..."
        sudo systemctl stop $CHAINLINK_SERVICE_NAME
    fi
    
    # Copy binary to system location
    if ! sudo cp "$GOPATH/bin/chainlink" /usr/local/bin/; then
        print_error "Failed to copy Chainlink binary to /usr/local/bin/"
        return 1
    fi
    sudo chmod +x $CHAINLINK_BINARY
    
    # Verify installation
    if ! command_exists chainlink; then
        print_error "Chainlink installation failed - chainlink command not found"
        return 1
    fi
    
    # Get actual installed version
    local installed_version
    installed_version=$($CHAINLINK_BINARY version 2>/dev/null | head -n1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' || echo "$chainlink_version")
    
    print_success "Chainlink $installed_version built and installed successfully"
}

# Function to completely clean up existing Chainlink installation
cleanup_chainlink() {
    print_status "Cleaning up existing Chainlink installation..."
    
    # Stop and disable service
    if sudo systemctl is-active --quiet $CHAINLINK_SERVICE_NAME; then
        print_status "Stopping Chainlink service..."
        sudo systemctl stop $CHAINLINK_SERVICE_NAME
    fi
    
    if sudo systemctl is-enabled --quiet $CHAINLINK_SERVICE_NAME; then
        print_status "Disabling Chainlink service..."
        sudo systemctl disable $CHAINLINK_SERVICE_NAME
    fi
    
    # Remove service file
    if [[ -f $CHAINLINK_SERVICE_FILE ]]; then
        print_status "Removing systemd service file..."
        sudo rm -f $CHAINLINK_SERVICE_FILE
        sudo systemctl daemon-reload
    fi
    
    # Remove chainlink user and home directory
    if id "$CHAINLINK_USER" &>/dev/null; then
        print_status "Removing chainlink user..."
        sudo userdel -r "$CHAINLINK_USER" 2>/dev/null || true
    fi
    
    # Remove chainlink directories
    if [[ -d "/home/$CHAINLINK_USER" ]]; then
        print_status "Removing chainlink home directory..."
        sudo rm -rf "/home/$CHAINLINK_USER"
    fi
    
    if [[ -d "$CHAINLINK_HOME" ]]; then
        print_status "Removing chainlink installation directory..."
        sudo rm -rf "$CHAINLINK_HOME"
    fi
    
    # Remove chainlink binary
    if [[ -f $CHAINLINK_BINARY ]]; then
        print_status "Removing chainlink binary..."
        sudo rm -f $CHAINLINK_BINARY
    fi
    
    # Remove credentials file
    if [[ -f $CREDENTIALS_FILE ]]; then
        print_status "Removing credentials file..."
        rm -f $CREDENTIALS_FILE
    fi
    
    # Clean up database
    print_status "Cleaning up database..."
    sudo -u postgres psql -c "DROP DATABASE IF EXISTS $CHAINLINK_DB_NAME;" 2>/dev/null || true
    sudo -u postgres psql -c "DROP USER IF EXISTS $CHAINLINK_DB_USER;" 2>/dev/null || true
    
    print_success "Cleanup completed"
}

# Function to setup Chainlink configuration directory
create_chainlink_config() {
    print_status "Setting up Chainlink configuration directory..."
    
    # Create configuration directory in the chainlink user's home directory
    sudo mkdir -p /home/$CHAINLINK_USER/.chainlink
    
    # Copy configuration files from script directory to the .chainlink directory
    print_status "Looking for config.toml and secrets.toml files in script directory: $SCRIPT_DIR"
    
    if [[ -f "$SCRIPT_DIR/config.toml" ]]; then
        sudo cp "$SCRIPT_DIR/config.toml" /home/$CHAINLINK_USER/.chainlink/
        print_status "Copied config.toml to /home/$CHAINLINK_USER/.chainlink/"
    else
        print_error "config.toml not found in script directory: $SCRIPT_DIR"
        print_error "Please ensure config.toml is in the same directory as setup.sh"
        return 1
    fi
    
    if [[ -f "$SCRIPT_DIR/secrets.toml" ]]; then
        # Force remove any existing corrupted file
        sudo rm -f /home/$CHAINLINK_USER/.chainlink/secrets.toml
        # Copy the correct file
        sudo cp "$SCRIPT_DIR/secrets.toml" /home/$CHAINLINK_USER/.chainlink/
        print_status "Copied secrets.toml to /home/$CHAINLINK_USER/.chainlink/"
    else
        print_error "secrets.toml not found in script directory: $SCRIPT_DIR"
        print_error "Please ensure secrets.toml is in the same directory as setup.sh"
        return 1
    fi
    
    # Set ownership and permissions
    sudo chown -R $CHAINLINK_USER:$CHAINLINK_GROUP /home/$CHAINLINK_USER/.chainlink
    sudo chmod 600 /home/$CHAINLINK_USER/.chainlink/config.toml
    sudo chmod 600 /home/$CHAINLINK_USER/.chainlink/secrets.toml
    
    # Remove any example secrets.toml files that might interfere
    print_status "Cleaning up example configuration files..."
    sudo rm -f /tmp/chainlink/core/config/docs/secrets.toml
    sudo rm -f /tmp/chainlink/core/config/docs/config.toml
    sudo find /tmp -name "secrets.toml" -path "*/docs/*" -delete 2>/dev/null || true
    sudo find /tmp -name "config.toml" -path "*/docs/*" -delete 2>/dev/null || true
    
    print_success "Chainlink configuration directory setup complete"
}

# Function to create systemd service
create_systemd_service() {
    print_status "Creating systemd service..."
    
    # Force stop and disable the service if it exists
    if systemctl is-active --quiet $CHAINLINK_SERVICE_NAME 2>/dev/null; then
        print_status "Stopping existing Chainlink service..."
        sudo systemctl stop $CHAINLINK_SERVICE_NAME
    fi
    
    if systemctl is-enabled --quiet $CHAINLINK_SERVICE_NAME 2>/dev/null; then
        print_status "Disabling existing Chainlink service..."
        sudo systemctl disable $CHAINLINK_SERVICE_NAME
    fi
    
    # Remove old service file completely
    if [[ -f $CHAINLINK_SERVICE_FILE ]]; then
        print_status "Removing old service file..."
        sudo rm -f $CHAINLINK_SERVICE_FILE
    fi
    
    # Create new service file
    print_status "Creating new systemd service file..."
    sudo tee $CHAINLINK_SERVICE_FILE > /dev/null << EOF
[Unit]
Description=Chainlink Node
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=$CHAINLINK_USER
Group=$CHAINLINK_GROUP
WorkingDirectory=/home/$CHAINLINK_USER
ExecStart=$CHAINLINK_BINARY -c /home/$CHAINLINK_USER/.chainlink/config.toml -s /home/$CHAINLINK_USER/.chainlink/secrets.toml node start -a /home/$CHAINLINK_USER/.chainlink/api
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=chainlink


# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/home/$CHAINLINK_USER $CHAINLINK_HOME $CHAINLINK_LOG_DIR
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
EOF

    # Force reload systemd and enable service
    print_status "Reloading systemd and enabling service..."
    sudo systemctl daemon-reload
    sudo systemctl enable $CHAINLINK_SERVICE_NAME
    
    # Force reload again to ensure changes take effect
    sudo systemctl daemon-reload
    
    print_success "Systemd service created and enabled"
}

# Function to setup Caddy reverse proxy
setup_caddy() {
    print_status "Setting up Caddy reverse proxy..."
    
    # Install Caddy if not already installed
    if ! command_exists caddy; then
        print_status "Installing Caddy..."
        sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
        sudo apt update
        sudo apt install -y caddy
    fi
    
    # Create Caddyfile configuration
    sudo tee /etc/caddy/Caddyfile > /dev/null << 'EOF'
chainlink.brassey.io {
    reverse_proxy localhost:6688
    
    header {
        # Enable HSTS
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        # Prevent clickjacking
        X-Frame-Options "SAMEORIGIN"
        # Prevent MIME type sniffing
        X-Content-Type-Options "nosniff"
    }
    
    # Enable automatic HTTPS with Let's Encrypt
    tls admin@brassey.io
    
    # Enable logging
    log {
        output file /var/log/caddy/chainlink.log
        format json
    }
}
EOF

    # Create log directory
    sudo mkdir -p /var/log/caddy
    sudo chown caddy:caddy /var/log/caddy
    
    # Restart Caddy
    sudo systemctl restart caddy
    sudo systemctl enable caddy
    
    print_success "Caddy reverse proxy configured with automatic HTTPS"
}

# Function to generate SSL certificates (not needed with Caddy - it handles it automatically)
generate_ssl_certs() {
    print_status "SSL certificates will be automatically managed by Caddy..."
    print_success "Caddy will automatically obtain and renew Let's Encrypt certificates"
    
    # Check if certificate already exists
    if [[ -f "/etc/letsencrypt/live/chainlink.brassey.io/fullchain.pem" ]]; then
        print_success "SSL certificate already exists"
        return 0
    fi
    
    # Stop any service that might be using port 80
    sudo systemctl stop chainlink 2>/dev/null || true
    
    # Generate Let's Encrypt certificate
    print_status "Generating Let's Encrypt certificate for chainlink.brassey.io..."
    print_warning "Make sure DNS is pointing to this server and ports 80/443 are open"
    
    sudo certbot certonly --standalone --non-interactive --agree-tos --email admin@brassey.io -d chainlink.brassey.io
    
    if [[ $? -eq 0 ]]; then
        print_success "SSL certificate generated successfully"
        
        # Set up automatic renewal
        print_status "Setting up automatic certificate renewal..."
        sudo systemctl enable certbot.timer
        sudo systemctl start certbot.timer
    else
        print_error "Failed to generate SSL certificate"
        print_warning "Falling back to self-signed certificate for testing..."
        
        # Create TLS directory
        sudo mkdir -p /etc/letsencrypt/live/chainlink.brassey.io
        
        # Generate self-signed certificate as fallback
        sudo openssl req -x509 -newkey rsa:4096 -keyout /etc/letsencrypt/live/chainlink.brassey.io/privkey.pem -out /etc/letsencrypt/live/chainlink.brassey.io/fullchain.pem -days 365 -nodes -subj "/CN=chainlink.brassey.io"
        
        print_warning "Using self-signed certificate. Run certbot manually to get a valid certificate."
    fi
}

# Function to create admin credentials
create_admin_credentials() {
    print_status "Creating admin credentials..."
    
    # Generate random admin password
    ADMIN_PASSWORD=$(openssl rand -base64 32)
    
    # Create credentials file with email and password
    sudo tee /home/$CHAINLINK_USER/.chainlink/api > /dev/null << EOF
$ADMIN_USERNAME@example.com
$ADMIN_PASSWORD
EOF

    # Set ownership and permissions
    sudo chown $CHAINLINK_USER:$CHAINLINK_GROUP /home/$CHAINLINK_USER/.chainlink/api
    sudo chmod 600 /home/$CHAINLINK_USER/.chainlink/api
    
    # Save credentials to a file for user reference
    echo "Chainlink Admin Credentials:" > $CREDENTIALS_FILE
    echo "Username: $ADMIN_USERNAME" >> $CREDENTIALS_FILE
    echo "Password: $ADMIN_PASSWORD" >> $CREDENTIALS_FILE
    echo "Web UI: http://localhost:$CHAINLINK_WEB_PORT" >> $CREDENTIALS_FILE
    echo "Database: $CHAINLINK_DB_NAME" >> $CREDENTIALS_FILE
    echo "Database User: $CHAINLINK_DB_USER" >> $CREDENTIALS_FILE
    echo "Database Password: (see secrets.toml)" >> $CREDENTIALS_FILE
    
    print_success "Admin credentials ready and saved to $CREDENTIALS_FILE"
}

# Function to test Ethereum connection
test_ethereum_connection() {
    print_status "Testing connection to Ethereum node..."
    print_status "HTTP URL: $ETHEREUM_NODE_URL"
    print_status "WebSocket URL: $ETHEREUM_WS_URL"
    
    local http_success=false
    local ws_success=false
    
    # Test HTTPS connection with authentication
    print_status "Testing HTTPS RPC connection with authentication..."
    local http_response
    http_response=$(curl -s --connect-timeout 15 --max-time 30 -X POST \
        -H "Content-Type: application/json" \
        -u "$ADMIN_USERNAME:$DEFAULT_PASSWORD" \
        -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
        $ETHEREUM_NODE_URL 2>/dev/null)
    
    if [[ $? -eq 0 && -n "$http_response" ]]; then
        # Check if response contains valid JSON-RPC response
        local block_number
        block_number=$(echo "$http_response" | jq -r '.result' 2>/dev/null)
        if [[ "$block_number" != "null" && "$block_number" != "" ]]; then
            print_success "HTTP RPC connection successful - Latest block: $block_number"
            http_success=true
        else
            print_error "HTTP RPC returned invalid response: $http_response"
        fi
    else
        print_error "HTTP RPC connection failed - Cannot reach $ETHEREUM_NODE_URL"
    fi
    
    # Test additional HTTP methods
    if [[ "$http_success" == true ]]; then
        print_status "Testing additional RPC methods..."
        
        # Test eth_chainId
        local chain_id_response
        chain_id_response=$(curl -s --connect-timeout 10 -X POST \
            -H "Content-Type: application/json" \
            -u "$ADMIN_USERNAME:$DEFAULT_PASSWORD" \
            -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
            $ETHEREUM_NODE_URL 2>/dev/null | jq -r '.result' 2>/dev/null)
        
        if [[ "$chain_id_response" != "null" && "$chain_id_response" != "" ]]; then
            local chain_id_dec=$((chain_id_response))
            print_success "Chain ID: $chain_id_dec ($chain_id_response)"
        fi
        
        # Test eth_syncing
        local syncing_response
        syncing_response=$(curl -s --connect-timeout 10 -X POST \
            -H "Content-Type: application/json" \
            -u "$ADMIN_USERNAME:$DEFAULT_PASSWORD" \
            -d '{"jsonrpc":"2.0","method":"eth_syncing","params":[],"id":1}' \
            $ETHEREUM_NODE_URL 2>/dev/null | jq -r '.result' 2>/dev/null)
        
        if [[ "$syncing_response" == "false" ]]; then
            print_success "Node is fully synced"
        elif [[ "$syncing_response" != "null" ]]; then
            print_warning "Node is still syncing - this is normal for archival nodes"
        fi
    fi
    
    # Test WebSocket connection (WSS with authentication)
    print_status "Testing WebSocket connection..."
    if timeout 15 websocat -t "$ETHEREUM_WS_URL" > /dev/null 2>&1; then
        print_success "WebSocket connection successful"
        ws_success=true
    else
        print_warning "WebSocket connection failed - may require authentication or different setup"
    fi
    
    # Summary and recommendations
    echo
    print_status "Ethereum Node Connectivity Summary:"
    if [[ "$http_success" == true ]]; then
        print_success "✓ HTTP RPC connection working"
    else
        print_error "✗ HTTP RPC connection failed"
    fi
    
    if [[ "$ws_success" == true ]]; then
        print_success "✓ WebSocket connection working"
    else
        print_warning "✗ WebSocket connection failed (optional but recommended)"
    fi
    
    # Final validation
    if [[ "$http_success" == true ]]; then
        print_success "Ethereum node is reachable and ready for Chainlink"
        return 0
    else
        print_error "Ethereum node is not reachable!"
        print_error "Please check:"
        print_error "1. The Ethereum node is running and accessible"
        print_error "2. The URL is correct: $ETHEREUM_NODE_URL"
        print_error "3. Firewall allows connections on port 8545"
        print_error "4. The node accepts external connections"
        return 1
    fi
}

# Function to start Chainlink service
start_chainlink() {
    print_status "Starting Chainlink service..."
    
    # Check if service is already running and healthy
    if sudo systemctl is-active --quiet $CHAINLINK_SERVICE_NAME && curl -s http://localhost:$CHAINLINK_WEB_PORT > /dev/null 2>&1; then
        print_success "Chainlink service is already running and healthy"
        return 0
    fi
    
    # Stop service if it's running but not healthy
    if sudo systemctl is-active --quiet $CHAINLINK_SERVICE_NAME; then
        print_status "Stopping unhealthy service to restart..."
        sudo systemctl stop $CHAINLINK_SERVICE_NAME
        sleep 3
    fi
    
    # Start the service
    sudo systemctl start $CHAINLINK_SERVICE_NAME
    
    # Wait for service to start
    sleep 15
    
    # Check if service is actually running and healthy
    if sudo systemctl is-active --quiet $CHAINLINK_SERVICE_NAME; then
        # Additional check: try to connect to the web UI
        sleep 5
        if curl -s http://localhost:$CHAINLINK_WEB_PORT > /dev/null 2>&1; then
            print_success "Chainlink service started successfully"
        else
            print_error "Chainlink service is running but web UI is not accessible"
            print_status "Checking service logs..."
            sudo journalctl -u $CHAINLINK_SERVICE_NAME --no-pager -n 10
            return 1
        fi
    else
        print_error "Chainlink service failed to start"
        print_status "Checking service logs..."
        sudo journalctl -u $CHAINLINK_SERVICE_NAME --no-pager -n 10
        print_warning "Service failed to start. Check logs above for details."
        return 1
    fi
}

# Function to display final information
display_final_info() {
    # Check if service is actually working
    if sudo systemctl is-active --quiet $CHAINLINK_SERVICE_NAME && curl -s http://localhost:$CHAINLINK_WEB_PORT > /dev/null 2>&1; then
        print_success "Chainlink node setup completed successfully!"
        echo
        echo "=== CHAINLINK NODE INFORMATION ==="
        echo "Service Status: $(sudo systemctl is-active $CHAINLINK_SERVICE_NAME)"
        echo "Web UI: http://localhost:$CHAINLINK_WEB_PORT"
        echo "Credentials: $CREDENTIALS_FILE"
        echo "Logs: sudo journalctl -u $CHAINLINK_SERVICE_NAME -f"
        echo "Config: /home/$CHAINLINK_USER/.chainlink/"
        echo "Database: $CHAINLINK_DB_NAME"
        echo "Ethereum Node: $ETHEREUM_NODE_URL"
        echo "Installed Versions:"
        echo "  - Go: $GO_VERSION"
        echo "  - Node.js: $NODE_VERSION"
        echo "  - pnpm: $PNPM_VERSION"
        echo "  - PostgreSQL: $POSTGRES_VERSION"
        echo "  - Chainlink: $($CHAINLINK_BINARY version 2>/dev/null | head -n1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' || echo 'Unknown')"
        echo
        echo "=== USEFUL COMMANDS ==="
        echo "Start service: sudo systemctl start chainlink"
        echo "Stop service: sudo systemctl stop chainlink"
        echo "Restart service: sudo systemctl restart chainlink"
        echo "View logs: sudo journalctl -u $CHAINLINK_SERVICE_NAME -f"
        echo "Check status: sudo systemctl status $CHAINLINK_SERVICE_NAME"
        echo
        echo "=== NEXT STEPS ==="
        echo "1. Access the web UI at http://localhost:$CHAINLINK_WEB_PORT"
        echo "2. Login with credentials from $CREDENTIALS_FILE"
        echo "3. Configure your node settings in the web UI"
        echo "4. Create jobs to start using your Chainlink node"
        echo
        print_warning "Please save the credentials file ($CREDENTIALS_FILE) in a secure location!"
    else
        print_error "Chainlink node setup FAILED!"
        echo
        echo "=== SERVICE STATUS ==="
        echo "Service Status: $(sudo systemctl is-active $CHAINLINK_SERVICE_NAME)"
        echo "Web UI: http://localhost:$CHAINLINK_WEB_PORT (NOT ACCESSIBLE)"
        echo
        echo "=== TROUBLESHOOTING ==="
        echo "1. Check service logs: sudo journalctl -u $CHAINLINK_SERVICE_NAME -f"
        echo "2. Check service status: sudo systemctl status $CHAINLINK_SERVICE_NAME"
        echo "3. Verify configuration files are in: /home/$CHAINLINK_USER/.chainlink/"
        echo "4. Ensure database is running: sudo systemctl status postgresql"
        echo
        print_warning "The Chainlink service is not working properly. Please check the logs and configuration."
        return 1
    fi
}

# Load configuration from .env file
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    print_status "Loading configuration from .env file..."
    # Export all variables from .env file
    set -a  # automatically export all variables
    source "$SCRIPT_DIR/.env"
    set +a  # stop automatically exporting
    print_success "Configuration loaded from .env file"
else
    print_error ".env file not found in $SCRIPT_DIR"
    print_error "Please create a .env file with your configuration"
    exit 1
fi

# Main execution
main() {
    print_status "Starting Chainlink node setup..."
    print_status "Target Ethereum node: $ETHEREUM_NODE_URL"
    print_status "This script will install the latest versions of all dependencies"
    print_status "Script directory: $SCRIPT_DIR"
    echo
    
    # Display configuration summary
    print_status "Chainlink Node Setup Configuration:"
    echo
    echo "=== ETHEREUM NODE ==="
    echo "HTTP URL: $ETHEREUM_NODE_URL"
    echo "WebSocket URL: $ETHEREUM_WS_URL"
    echo
    echo "=== CHAINLINK NODE ==="
    echo "User: $CHAINLINK_USER"
    echo "Home: $CHAINLINK_HOME"
    echo "Database: $CHAINLINK_DB_NAME"
    echo
    
    # Check prerequisites
    check_config_files
    check_network
    check_root
    
    # Test Ethereum connection early (fail fast if not reachable)
    test_ethereum_connection
    
    # Clean up any existing installation
    cleanup_chainlink
    
    # Install dependencies
    install_system_dependencies
    install_websocat
    install_go
    setup_go_environment
    install_nodejs
    setup_postgresql
    setup_chainlink_user
    
    # Build and configure Chainlink
    build_chainlink
    create_chainlink_config
    setup_caddy
    create_systemd_service
    create_admin_credentials
    
    # Start Chainlink
    start_chainlink
    
    # Display final information
    display_final_info
}

# Run main function
main "$@"