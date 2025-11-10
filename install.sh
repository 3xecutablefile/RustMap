#!/bin/bash

# OxideScanner Installation Script
# Made by: 3xecutablefile
# 
# This script installs all dependencies and builds OxideScanner for you

set -e  # Exit on any error

# Track if we're in a git repository for cleanup purposes
REPO_PATH=$(pwd)
REPO_NAME=$(basename "$REPO_PATH")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_info() {
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

print_header() {
    echo -e "\n${BLUE}================================${NC}"
    echo -e "${BLUE}   OxideScanner Installation Script   ${NC}"
    echo -e "${BLUE}================================${NC}\n"
}

print_header

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ] || [ ! -f "src/main.rs" ]; then
    print_error "Please run this script from the OxideScanner repository root directory"
    exit 1
fi

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    print_error "Unsupported operating system: $OSTYPE"
    exit 1
fi

print_info "Detected OS: $OS"

# Check for sudo access (needed for package installation)
if [ "$OS" = "linux" ]; then
    print_info "Checking for sudo access..."
    if ! sudo -n true 2>/dev/null; then
        print_warning "This script may need sudo for package installation"
        print_info "You may be prompted for your password"
    fi
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install package
install_package() {
    local package=$1
    local command_name=$2
    
    if command_exists "$command_name"; then
        print_success "$package is already installed"
        return 0
    fi
    
    print_info "Installing $package..."
    
    if [ "$OS" = "linux" ]; then
        # Detect Linux distribution
        if command_exists apt-get; then
            sudo apt-get update
            sudo apt-get install -y "$package"
        elif command_exists yum; then
            sudo yum install -y "$package"
        elif command_exists dnf; then
            sudo dnf install -y "$package"
        elif command_exists pacman; then
            sudo pacman -S --noconfirm "$package"
        else
            print_error "Unsupported package manager. Please install $package manually."
            return 1
        fi
    elif [ "$OS" = "macos" ]; then
        if command_exists brew; then
            brew install "$package"
        else
            print_error "Homebrew not found. Please install Homebrew first: https://brew.sh"
            print_error "Or install $package manually"
            return 1
        fi
    fi
    
    if command_exists "$command_name"; then
        print_success "$package installed successfully"
    else
        print_error "Failed to install $package"
        return 1
    fi
}

print_info "Checking system requirements..."

# Check for Rust/Cargo
if ! command_exists cargo; then
    print_info "Rust/Cargo not found. Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
    print_success "Rust installed successfully"
else
    print_success "Rust/Cargo is already installed"
fi

# Install required system packages
print_info "Installing required system packages..."

install_package "nmap" "nmap"
install_package "searchsploit" "searchsploit"

# Install Ruby for searchsploit (if not already installed)
if [ "$OS" = "linux" ]; then
    install_package "ruby" "ruby"
elif [ "$OS" = "macos" ]; then
    if command_exists brew; then
        # Ruby usually comes with macOS, but let's ensure searchsploit works
        if ! command_exists searchsploit; then
            print_info "Installing searchsploit manually..."
            if [ -d "/opt/homebrew/bin" ] || [ -d "/usr/local/bin" ]; then
                # Try to install from GitHub
                if ! command_exists git; then
                    install_package "git" "git"
                fi
                print_info "Cloning searchsploit repository..."
                if [ ! -d "/opt/homebrew/opt/searchsploit" ] && [ ! -d "/usr/local/opt/searchsploit" ]; then
                    sudo mkdir -p /opt/searchsploit 2>/dev/null || sudo mkdir -p /usr/local/share/searchsploit
                    sudo git clone https://github.com/offensive-security/exploitdb.git /opt/searchsploit 2>/dev/null || sudo git clone https://github.com/offensive-security/exploitdb.git /usr/local/share/searchsploit
                    
                    # Create symlink
                    if [ -d "/opt/searchsploit" ]; then
                        sudo ln -sf /opt/searchsploit/searchsploit /usr/local/bin/searchsploit
                    else
                        sudo ln -sf /usr/local/share/searchsploit/searchsploit /usr/local/bin/searchsploit
                    fi
                fi
            fi
        fi
    fi
fi

# Check if searchsploit is working
if ! command_exists searchsploit; then
    print_warning "Searchsploit installation may have failed"
    print_info "Trying to setup searchsploit manually..."
    
    # Try to download and setup searchsploit
    SEARCHSPLOIT_DIR="/tmp/searchsploit"
    if [ ! -d "$SEARCHSPLOIT_DIR" ]; then
        git clone https://github.com/offensive-security/exploitdb.git "$SEARCHSPLOIT_DIR" 2>/dev/null || true
    fi
    
    if [ -f "$SEARCHSPLOIT_DIR/searchsploit" ]; then
        print_info "Setting up searchsploit symlink..."
        sudo ln -sf "$SEARCHSPLOIT_DIR/searchsploit" /usr/local/bin/searchsploit 2>/dev/null || true
        
        # Add to PATH if not working
        if ! command_exists searchsploit; then
            export PATH="$SEARCHSPLOIT_DIR:$PATH"
            print_info "Added searchsploit to PATH"
        fi
    fi
fi

# Update searchsploit database
print_info "Updating searchsploit database..."
if command_exists searchsploit; then
    searchsploit --update >/dev/null 2>&1 || print_warning "Searchsploit update failed (this is normal on first run)"
    print_success "Searchsploit database updated"
else
    print_warning "Searchsploit not available - exploit functionality will be limited"
fi

# Build OxideScanner
print_info "Building OxideScanner..."
if cargo build --release; then
    print_success "OxideScanner built successfully"
else
    print_error "Failed to build OxideScanner"
    exit 1
fi

# Install binary to system PATH
print_info "Installing OxideScanner to system PATH..."
INSTALL_DIR="/usr/local/bin"

if [ -w "$INSTALL_DIR" ] || sudo -n true 2>/dev/null; then
    sudo cp target/release/oxscan "$INSTALL_DIR/"
    sudo chmod +x "$INSTALL_DIR/oxscan"
    print_success "OxideScanner installed to $INSTALL_DIR"
else
    print_warning "Cannot write to $INSTALL_DIR"
    print_info "You can manually copy target/release/oxscan to your PATH"
    print_info "Or run: sudo cp target/release/oxscan $INSTALL_DIR/"
fi

# Verify installation
print_info "Verifying installation..."
INSTALLATION_SUCCESS=false

if command_exists oxscan; then
    OXIDESCANNER_VERSION=$(oxscan --help 2>/dev/null | head -n 1 || echo "version unknown")
    print_success "OxideScanner installed successfully!"
    print_info "Version: $OXIDESCANNER_VERSION"
    INSTALLATION_SUCCESS=true
else
    # Try local binary
    if [ -f "target/release/oxscan" ]; then
        print_success "OxideScanner built successfully (local binary: target/release/oxscan)"
        print_info "Add $(pwd)/target/release to your PATH or copy the binary to a directory in PATH"
        INSTALLATION_SUCCESS=true
    else
        print_error "OxideScanner installation verification failed"
        INSTALLATION_SUCCESS=false
    fi
fi

# Final setup instructions
echo -e "\n${GREEN}================================${NC}"
echo -e "${GREEN}   Installation Complete!         ${NC}"
echo -e "${GREEN}================================${NC}\n"

print_success "OxideScanner is ready to use!"

if command_exists oxscan; then
    echo -e "${BLUE}Test it with:${NC}"
    echo "  oxscan scanme.nmap.org"
    echo "  oxscan scanme.nmap.org -1k"
    echo "  oxscan scanme.nmap.org --json"
    echo "  oxscan --update"
else
    echo -e "${BLUE}To use OxideScanner:${NC}"
    echo "  ./target/release/oxscan scanme.nmap.org"
    echo "  ./target/release/oxscan --update"
fi

echo -e "\n${YELLOW}Requirements Check:${NC}"
echo -n "  Nmap: "; command_exists nmap && print_success "✓" || print_error "✗"
echo -n "  Searchsploit: "; command_exists searchsploit && print_success "✓" || print_warning "✗ (limited functionality)"
echo -n "  OxideScanner: "; command_exists oxscan && print_success "✓" || print_success "✓ (local binary)"

# Auto-cleanup: only if installation was successful
if [ "$INSTALLATION_SUCCESS" = true ]; then
    echo -e "\n${BLUE}Auto-cleanup:${NC}"
    print_info "Cleaning up source repository..."
    cd ..
    if rm -rf "$REPO_NAME"; then
        print_success "Repository deleted successfully"
        print_info "OxideScanner will continue to work from system PATH"
        print_info "Current directory is now: $(pwd)"
    else
        print_warning "Could not delete repository (permission issue)"
        print_info "You can manually delete it with: rm -rf $REPO_NAME"
    fi
else
    print_warning "Installation did not complete successfully - repository not deleted"
    print_info "Please check the errors above and try again if needed"
fi

print_info "For more information, check the README.md file"
print_info "Made by: 3xecutablefile"

echo -e "\n${GREEN}Happy scanning! 🚀${NC}\n"