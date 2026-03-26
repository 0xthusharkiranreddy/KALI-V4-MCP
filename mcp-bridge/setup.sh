#!/bin/bash

# Kali Pentest MCP Server - Setup and Management Script
# This script automates the deployment and management of the Kali-Pentest-MCP Server

set -e  # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
info() {
    echo -e "${BLUE}ℹ ${NC}$1"
}

success() {
    echo -e "${GREEN}✓ ${NC}$1"
}

warning() {
    echo -e "${YELLOW}⚠ ${NC}$1"
}

error() {
    echo -e "${RED}✗ ${NC}$1"
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Display banner
show_banner() {
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════╗"
    echo "║   Kali Pentest MCP Server - Setup Manager        ║"
    echo "║   Docker-based Penetration Testing Bridge        ║"
    echo "╚═══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Check prerequisites
check_prerequisites() {
    info "Checking prerequisites..."

    # Check for Docker
    if ! command_exists docker; then
        error "Docker is not installed. Please install Docker first."
        echo "Visit: https://docs.docker.com/get-docker/"
        exit 1
    fi
    success "Docker is installed"

    # Check for Docker Compose
    if ! docker compose version &> /dev/null; then
        error "Docker Compose is not installed. Please install Docker Compose."
        echo "Visit: https://docs.docker.com/compose/install/"
        exit 1
    fi
    success "Docker Compose is installed"

    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        error "Docker daemon is not running. Please start Docker."
        exit 1
    fi
    success "Docker daemon is running"
}

# Setup configuration
setup_config() {
    info "Setting up configuration..."

    # Check if .env file exists
    if [ ! -f .env ]; then
        if [ -f .env.example ]; then
            cp .env.example .env
            success "Created .env file from .env.example"
        else
            error ".env.example file not found!"
            exit 1
        fi

        warning "Please edit the .env file with your Kali Linux connection details:"
        echo ""
        echo "  KALI_HOST=your-kali-hostname.com"
        echo "  KALI_PORT=22"
        echo "  KALI_USERNAME=kali"
        echo "  COMMAND_TIMEOUT=900000"
        echo ""
        read -p "Press Enter to open .env file for editing..."
        ${EDITOR:-nano} .env
    else
        success ".env file already exists"
    fi
}

# Setup SSH keys
setup_ssh_keys() {
    info "Setting up SSH keys..."

    # Create ssh-keys directory if it doesn't exist
    if [ ! -d ssh-keys ]; then
        mkdir -p ssh-keys
        chmod 700 ssh-keys
        success "Created ssh-keys directory"
    fi

    # Check if SSH key already exists
    if [ -f ssh-keys/id_ed25519 ]; then
        success "SSH key already exists"
        return 0
    fi

    # Generate SSH key
    info "Generating new SSH key pair (ED25519)..."
    ssh-keygen -t ed25519 -f ssh-keys/id_ed25519 -N "" -C "kali-mcp-server"

    # Set proper permissions
    chmod 600 ssh-keys/id_ed25519
    chmod 644 ssh-keys/id_ed25519.pub

    success "SSH key pair generated successfully"
    echo ""
    warning "IMPORTANT: Copy the following public key to your Kali Linux machine"
    echo ""
    echo -e "${GREEN}Public Key:${NC}"
    cat ssh-keys/id_ed25519.pub
    echo ""
    echo "To add this key to your Kali Linux machine, run on the Kali host:"
    echo -e "${YELLOW}echo '$(cat ssh-keys/id_ed25519.pub)' >> ~/.ssh/authorized_keys${NC}"
    echo ""
    echo "Or use ssh-copy-id:"

    # Read KALI_HOST and KALI_USERNAME from .env if it exists
    if [ -f .env ]; then
        source .env
        echo -e "${YELLOW}ssh-copy-id -i ssh-keys/id_ed25519.pub ${KALI_USERNAME}@${KALI_HOST}${NC}"
    fi
    echo ""
    read -p "Press Enter once you have copied the public key to your Kali machine..."
}

# Test SSH connection
test_ssh_connection() {
    info "Testing SSH connection to Kali Linux machine..."

    if [ ! -f .env ]; then
        warning "No .env file found. Skipping SSH connection test."
        return 1
    fi

    source .env

    info "Attempting to connect to ${KALI_USERNAME}@${KALI_HOST}:${KALI_PORT}..."

    if ssh -i ssh-keys/id_ed25519 -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        -p "${KALI_PORT}" "${KALI_USERNAME}@${KALI_HOST}" "echo 'SSH connection successful'" &> /dev/null; then
        success "SSH connection to Kali Linux machine is working!"
        return 0
    else
        error "Failed to connect to Kali Linux machine via SSH"
        warning "Please verify:"
        echo "  1. KALI_HOST, KALI_PORT, and KALI_USERNAME are correct in .env"
        echo "  2. SSH public key is added to ~/.ssh/authorized_keys on Kali machine"
        echo "  3. SSH service is running on Kali machine"
        echo "  4. Firewall allows SSH connections"
        return 1
    fi
}

# Create logs directory
setup_logs() {
    if [ ! -d logs ]; then
        mkdir -p logs
        success "Created logs directory"
    fi
}

# Initial setup
initial_setup() {
    show_banner
    info "Running initial setup..."
    echo ""

    check_prerequisites
    setup_config
    setup_ssh_keys
    setup_logs

    echo ""
    success "Initial setup complete!"
    echo ""
    info "You can now start the server using option 1 from the main menu."
    echo ""
    read -p "Press Enter to continue to main menu..."
}

# Start the server
start_server() {
    show_banner
    info "Starting Kali Pentest MCP Server..."

    # Check if setup is complete
    if [ ! -f .env ]; then
        warning "Configuration not found. Running initial setup..."
        initial_setup
    fi

    if [ ! -f ssh-keys/id_ed25519 ]; then
        warning "SSH keys not found. Running SSH key setup..."
        setup_ssh_keys
    fi

    info "Building and starting Docker containers..."
    docker compose up -d --build

    sleep 3

    # Check if containers are running
    if docker compose ps | grep -q "Up"; then
        success "Kali Pentest MCP Server is running!"
        echo ""
        info "Server Status:"
        docker compose ps
        echo ""
        success "Bridge API is available at: http://localhost:3001"
        echo ""
        echo "Test the health endpoint:"
        echo -e "${YELLOW}curl http://localhost:3001/health${NC}"
        echo ""
        echo "Execute a test command:"
        echo -e "${YELLOW}curl -X POST http://localhost:3001/v1/tools/execute -H 'Content-Type: application/json' -d '{\"tool_name\":\"execute_kali_command\",\"arguments\":{\"command\":\"whoami\"}}'${NC}"
        echo ""

        # Optional: Test SSH connection
        if test_ssh_connection; then
            echo ""
            success "SSH connection verified - server is fully operational!"
        fi
    else
        error "Failed to start containers. Check logs with: docker compose logs"
    fi
}

# Stop the server
stop_server() {
    show_banner
    info "Stopping Kali Pentest MCP Server..."

    docker compose down

    success "Kali Pentest MCP Server stopped"
}

# Restart the server
restart_server() {
    show_banner
    info "Restarting Kali Pentest MCP Server..."

    docker compose restart

    success "Kali Pentest MCP Server restarted"
    echo ""
    docker compose ps
}

# View logs
view_logs() {
    show_banner
    info "Viewing server logs (Press Ctrl+C to exit)..."
    echo ""

    docker compose logs -f
}

# Check status
check_status() {
    show_banner
    info "Checking server status..."
    echo ""

    echo -e "${BLUE}=== Container Status ===${NC}"
    docker compose ps
    echo ""

    echo -e "${BLUE}=== Resource Usage ===${NC}"
    docker stats --no-stream $(docker compose ps -q) 2>/dev/null || echo "No containers running"
    echo ""

    # Check if bridge API is responding
    if curl -s http://localhost:3001/health > /dev/null 2>&1; then
        success "Bridge API is responding at http://localhost:3001"
        echo "Response: $(curl -s http://localhost:3001/health)"
    else
        warning "Bridge API is not responding"
    fi
    echo ""

    # Check SSH connection
    if [ -f .env ]; then
        test_ssh_connection
    fi

    echo ""
    read -p "Press Enter to continue..."
}

# Update server
update_server() {
    show_banner
    info "Updating Kali Pentest MCP Server..."

    warning "This will pull the latest changes from git and rebuild containers."
    read -p "Continue? (y/n) " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        info "Pulling latest changes..."
        git pull

        info "Stopping containers..."
        docker compose down

        info "Rebuilding containers..."
        docker compose build --no-cache

        info "Starting containers..."
        docker compose up -d

        success "Server updated successfully!"
    else
        info "Update cancelled"
    fi
}

# Clean up
cleanup() {
    show_banner
    warning "This will remove all containers, volumes, and images."
    warning "Your configuration (.env) and SSH keys will be preserved."
    read -p "Are you sure? (y/n) " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        info "Cleaning up..."

        docker compose down -v
        docker system prune -f

        success "Cleanup complete"
    else
        info "Cleanup cancelled"
    fi
}

# Main menu
show_menu() {
    show_banner
    echo "Select an option:"
    echo ""
    echo "  1) Start Server"
    echo "  2) Stop Server"
    echo "  3) Restart Server"
    echo "  4) View Logs"
    echo "  5) Check Status"
    echo "  6) Update Server"
    echo "  7) Run Initial Setup"
    echo "  8) Test SSH Connection"
    echo "  9) Clean Up"
    echo "  0) Exit"
    echo ""
    read -p "Enter choice [0-9]: " choice
}

# Main loop
main() {
    # Check if this is first run
    if [ ! -f .env ] && [ ! -d ssh-keys ]; then
        initial_setup
    fi

    while true; do
        show_menu
        case $choice in
            1) start_server; read -p "Press Enter to continue..." ;;
            2) stop_server; read -p "Press Enter to continue..." ;;
            3) restart_server; read -p "Press Enter to continue..." ;;
            4) view_logs ;;
            5) check_status ;;
            6) update_server; read -p "Press Enter to continue..." ;;
            7) initial_setup ;;
            8) test_ssh_connection; read -p "Press Enter to continue..." ;;
            9) cleanup; read -p "Press Enter to continue..." ;;
            0)
                echo ""
                success "Goodbye!"
                exit 0
                ;;
            *)
                error "Invalid option. Please try again."
                sleep 2
                ;;
        esac
    done
}

# Run main function
main
