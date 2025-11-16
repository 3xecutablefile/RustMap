#!/bin/bash

# OxideScanner Installation Script
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_error() { echo -e "${RED}✗${NC} $1"; }
print_info() { echo -e "${BLUE}ℹ${NC} $1"; }
print_warning() { echo -e "${YELLOW}⚠${NC} $1"; }

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   OxideScanner Installation v1.0.1     ${NC}"
echo -e "${BLUE}   Intelligent Exploit Discovery        ${NC}"
echo -e "${BLUE}========================================${NC}"

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ] || [ ! -f "src/main.rs" ]; then
    print_error "Please run from OxideScanner repository root"
    exit 1
fi

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    print_error "Unsupported OS: $OSTYPE"
    exit 1
fi

print_info "Detected OS: $OS"

# Check if command exists
cmd_exists() { command -v "$1" >/dev/null 2>&1; }

# Install package
install_pkg() {
    local pkg=$1 cmd=$2
    if cmd_exists "$cmd"; then
        print_success "$pkg already installed"
        return
    fi

    print_info "Installing $pkg..."

    if [ "$OS" = "linux" ]; then
        if cmd_exists apt-get; then
            sudo apt-get update && sudo apt-get install -y "$pkg"
        elif cmd_exists yum; then
            sudo yum install -y "$pkg"
        elif cmd_exists dnf; then
            sudo dnf install -y "$pkg"
        else
            print_error "No supported package manager found"
            exit 1
        fi
    elif [ "$OS" = "macos" ]; then
        if cmd_exists brew; then
            brew install "$pkg"
        else
            print_error "Homebrew required. Install from https://brew.sh"
            exit 1
        fi
    fi
}

# Ensure sudo access is available
if [ "$EUID" -ne 0 ]; then
    print_info "This script requires sudo access for installing dependencies."
    print_info "You will be prompted for your password."
    sudo -v || { print_error "Sudo access is required for installation"; exit 1; }

    # Keep sudo timestamp updated throughout the installation
    (while true; do sudo -n true; sleep 60; kill -0 "$$" || exit; done) & SUDO_REFRESH_PID=$!
fi

# Install Rust
if ! cmd_exists cargo; then
    print_info "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
    print_success "Rust installed"
else
    print_success "Rust already installed"
fi

# Install system dependencies for Rust compilation
print_info "Installing system dependencies..."
if [ "$OS" = "linux" ]; then
    if cmd_exists apt-get; then
        print_info "Installing build-essential, pkg-config, and libssl-dev..."
        sudo apt-get update
        sudo apt-get install -y build-essential pkg-config libssl-dev
    elif cmd_exists yum; then
        sudo yum install -y gcc pkgconfig openssl-devel
    elif cmd_exists dnf; then
        sudo dnf install -y gcc pkgconfig openssl-devel
    else
        print_error "No supported package manager found for system dependencies"
        exit 1
    fi
fi

# Install application dependencies
print_info "Installing dependencies..."
install_pkg "nmap" "nmap"
install_pkg "Ruby" "ruby"

# Install searchsploit
if ! cmd_exists searchsploit; then
    print_info "Installing searchsploit..."
    if [ "$OS" = "linux" ]; then
        # Try package manager first
        if cmd_exists dnf; then
            print_info "Using DNF package manager to install exploitdb..."
            if sudo dnf install -y exploitdb; then
                print_success "exploitdb installed via DNF"
            else
                print_error "Failed to install exploitdb via DNF, trying manual installation"
                # Manual installation - Note: Official repo moved to GitLab
                if sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb; then
                    sudo cp -n /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
                    sudo chmod +x /usr/local/bin/searchsploit
                    # Update the database
                    sudo /opt/exploitdb/searchsploit -u
                    print_success "Manual installation completed"
                else
                    print_error "Manual installation failed"
                    exit 1
                fi
            fi
        elif cmd_exists yum; then
            print_info "Using YUM package manager to install exploitdb..."
            if sudo yum install -y exploitdb; then
                print_success "exploitdb installed via YUM"
            else
                print_error "Failed to install exploitdb via YUM, trying manual installation"
                # Manual installation - Note: Official repo moved to GitLab
                if sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb; then
                    sudo cp -n /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
                    sudo chmod +x /usr/local/bin/searchsploit
                    # Update the database
                    sudo /opt/exploitdb/searchsploit -u
                    print_success "Manual installation completed"
                else
                    print_error "Manual installation failed"
                    exit 1
                fi
            fi
        elif cmd_exists apt-get; then
            print_info "Using APT package manager to install exploitdb..."
            if sudo apt-get update && sudo apt-get install -y exploitdb; then
                print_success "exploitdb installed via APT"
            else
                print_error "Failed to install exploitdb via APT, trying manual installation"
                # Manual installation - Note: Official repo moved to GitLab
                if sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb; then
                    sudo cp -n /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
                    sudo chmod +x /usr/local/bin/searchsploit
                    # Update the database
                    sudo /opt/exploitdb/searchsploit -u
                    print_success "Manual installation completed"
                else
                    print_error "Manual installation failed"
                    exit 1
                fi
            fi
        else
            print_warning "No supported package manager found for exploitdb, using manual installation"
            # Manual installation - Note: Official repo moved to GitLab
            if sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb; then
                sudo cp -n /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
                sudo chmod +x /usr/local/bin/searchsploit
                # Update the database
                sudo /opt/exploitdb/searchsploit -u
                print_success "Manual installation completed"
            else
                print_error "Manual installation failed"
                exit 1
            fi
        fi
    elif [ "$OS" = "macos" ]; then
        if cmd_exists brew; then
            print_info "Using Homebrew to install exploitdb..."
            if brew install exploitdb; then
                print_success "exploitdb installed via Homebrew"
            else
                print_error "Failed to install exploitdb via Homebrew, trying manual installation"
                # Manual installation for macOS - Note: Official repo moved to GitLab
                if sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb; then
                    sudo cp -n /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
                    sudo chmod +x /usr/local/bin/searchsploit
                    # Update the database
                    sudo /opt/exploitdb/searchsploit -u
                    print_success "Manual installation completed"
                else
                    print_error "Manual installation failed"
                    exit 1
                fi
            fi
        else
            # Manual installation for macOS - Note: Official repo moved to GitLab
            print_info "Homebrew not found, using manual installation"
            if sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb; then
                sudo cp -n /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
                sudo chmod +x /usr/local/bin/searchsploit
                # Update the database
                sudo /opt/exploitdb/searchsploit -u
                print_success "Manual installation completed"
            else
                print_error "Manual installation failed"
                exit 1
            fi
        fi
    fi

    # Verify installation
    if cmd_exists searchsploit; then
        print_success "searchsploit installed"

        # Additional verification - check if searchsploit works
        if searchsploit -v 2>/dev/null | grep -q "Exploit Database\|searchsploit"; then
            print_success "searchsploit verification successful"
        else
            print_warning "searchsploit installed but basic verification failed"
            # Try to run a simple search to verify functionality
            if searchsploit test 2>/dev/null | head -5 | grep -q "Exploit Database\|Description\|Path"; then
                print_success "searchsploit functionality test passed"
            else
                print_error "searchsploit functionality test failed"
                exit 1
            fi
        fi

        # Verify searchsploit script is executable
        if [ -x "/usr/local/bin/searchsploit" ]; then
            print_success "searchsploit executable permissions OK"
        else
            print_error "searchsploit lacks execute permissions"
            sudo chmod +x /usr/local/bin/searchsploit
            if [ -x "/usr/local/bin/searchsploit" ]; then
                print_success "searchsploit permissions fixed"
            else
                print_error "could not set execute permissions on searchsploit"
                exit 1
            fi
        fi
    else
        print_error "searchsploit installation failed"
        exit 1
    fi
else
    print_success "searchsploit already installed"

    # Verify existing installation
    if searchsploit -v 2>/dev/null | grep -q "Exploit Database\|searchsploit"; then
        print_success "searchsploit verification successful"
    else
        print_warning "searchsploit found but verification failed - updating database"
        searchsploit -u 2>/dev/null || print_warning "Could not update exploitdb"

        # Test functionality after update
        if searchsploit test 2>/dev/null | head -5 | grep -q "Exploit Database\|Description\|Path"; then
            print_success "searchsploit functionality test passed after update"
        else
            print_warning "searchsploit may have issues after update"
        fi
    fi
fi

# Build OxideScanner
print_info "Building OxideScanner v1.0.1..."
print_info "Features: Intelligent query filtering + Real exploit data"
cargo build --release
print_success "Build complete"

# Install binary
print_info "Installing to system..."
INSTALL_DIR="/usr/local/bin"
if [ -w "$INSTALL_DIR" ] || sudo -n true 2>/dev/null; then
    sudo cp target/release/oxscan "$INSTALL_DIR/"
    sudo chmod +x "$INSTALL_DIR/oxscan"
    print_success "Installed to $INSTALL_DIR"
else
    print_warning "Cannot install to system PATH"
    print_info "Binary available at: $(pwd)/target/release/oxscan"
fi

# Final verification
echo -e "\n${GREEN}Installation Summary:${NC}"
cmd_exists nmap && print_success "nmap" || print_error "nmap"
cmd_exists searchsploit && print_success "searchsploit" || print_warning "searchsploit"

if cmd_exists oxscan; then
    print_success "oxscan (system)"
    echo -e "\n${GREEN}Ready to scan!${NC}"
    echo "  oxscan scanme.nmap.org"
    echo "  oxscan scanme.nmap.org -5k --json"
    echo ""
    echo "${BLUE}New in v1.0.1:${NC}"
    echo "  ✨ Intelligent exploit search - No more false positives"
    echo "  🎯 Only searches when specific service info is available"
    echo "  ⚡ Real searchsploit data instead of thousands of irrelevant results"
else
    print_success "oxscan (local)"
    echo -e "\n${GREEN}Ready to scan!${NC}"
    echo "  ./target/release/oxscan scanme.nmap.org"
fi

echo -e "\n${GREEN}Happy hacking! 🚀${NC}"