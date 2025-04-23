#!/bin/bash

# deploy_openvpn_webui.sh
# Script to automatically deploy openvpn-webui on various Linux distributions
# - Installs Python environment and required modules
# - Creates and enables a systemd service for openvpn-webui

# Exit on any error
set -e

# Default variables
OPENVPN_WEBUI_DIR="/opt/openvpn-webui"
SERVICE_NAME="openvpn-webui"
SERVICE_USER="root"
PYTHON_MIN_VERSION="3.8"
LOG_DIR="${OPENVPN_WEBUI_DIR}/log"
REQUIREMENTS_FILE="${OPENVPN_WEBUI_DIR}/requirements.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to log messages
log() {
    echo -e "${1}"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION_ID=$VERSION_ID
    else
        log "${RED}Error: Cannot detect Linux distribution (missing /etc/os-release)${NC}"
        exit 1
    fi
    log "${GREEN}Detected distribution: ${DISTRO} ${VERSION_ID}${NC}"
}

# Function to install Python and pip
install_python() {
    log "${YELLOW}Installing Python ${PYTHON_MIN_VERSION} and pip...${NC}"
    case "$DISTRO" in
        ubuntu|debian)
            sudo apt-get update
            sudo apt-get install -y python3 python3-pip python3-venv
            ;;
        centos|rhel)
            if [[ "$VERSION_ID" =~ ^7 ]]; then
                sudo yum install -y epel-release
                sudo yum install -y python3 python3-pip
            else
                sudo dnf install -y python3 python3-pip
            fi
            ;;
        fedora)
            sudo dnf install -y python3 python3-pip
            ;;
        *)
            log "${RED}Error: Unsupported distribution: ${DISTRO}${NC}"
            exit 1
            ;;
    esac

    # Verify Python version
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    if [[ "$(printf '%s\n' "${PYTHON_VERSION}" "${PYTHON_MIN_VERSION}" | sort -V | head -n1)" != "${PYTHON_MIN_VERSION}" ]]; then
        log "${RED}Error: Python ${PYTHON_VERSION} is installed, but ${PYTHON_MIN_VERSION} or higher is required${NC}"
        exit 1
    fi
    log "${GREEN}Python ${PYTHON_VERSION} and pip installed successfully${NC}"
}

# Function to install required Python modules
install_python_modules() {
    log "${YELLOW}Installing Python modules from ${REQUIREMENTS_FILE}...${NC}"
    if [ ! -f "${REQUIREMENTS_FILE}" ]; then
        log "${RED}Error: ${REQUIREMENTS_FILE} not found${NC}"
        exit 1
    fi

    # Create a virtual environment
    VENV_DIR="${OPENVPN_WEBUI_DIR}/venv"
    python3 -m venv "${VENV_DIR}"
    source "${VENV_DIR}/bin/activate"

    # Upgrade pip in virtual environment
    pip install --upgrade pip

    # Install requirements
    pip install -r "${REQUIREMENTS_FILE}"

    deactivate
    log "${GREEN}Python modules installed successfully${NC}"
}

# Function to create systemd service
create_systemd_service() {
    log "${YELLOW}Creating systemd service for ${SERVICE_NAME}...${NC}"
    SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
    WEBUI_PY="${OPENVPN_WEBUI_DIR}/bin/webui.py"
    VENV_PYTHON="${OPENVPN_WEBUI_DIR}/venv/bin/python3"

    if [ ! -f "${WEBUI_PY}" ]; then
        log "${RED}Error: ${WEBUI_PY} not found${NC}"
        exit 1
    fi

    if [ ! -f "${VENV_PYTHON}" ]; then
        log "${RED}Error: Virtual environment Python ${VENV_PYTHON} not found${NC}"
        exit 1
    fi

    # Create log directory if it doesn't exist
    sudo mkdir -p "${LOG_DIR}"
    sudo chown "${SERVICE_USER}:${SERVICE_USER}" "${LOG_DIR}"

    # Create systemd service file
    cat << EOF | sudo tee "${SERVICE_FILE}" > /dev/null
[Unit]
Description=OpenVPN WebUI Service
After=network.target

[Service]
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${OPENVPN_WEBUI_DIR}
ExecStart=${VENV_PYTHON} ${WEBUI_PY}
Restart=always
Environment="PYTHONPATH=${OPENVPN_WEBUI_DIR}"

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd, enable and start service
    sudo systemctl daemon-reload
    sudo systemctl enable "${SERVICE_NAME}"
    sudo systemctl start "${SERVICE_NAME}"

    # Check service status
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        log "${GREEN}Systemd service ${SERVICE_NAME} created and started successfully${NC}"
    else
        log "${RED}Error: Failed to start ${SERVICE_NAME} service${NC}"
        sudo systemctl status "${SERVICE_NAME}"
        exit 1
    fi
}

# Function to check prerequisites
check_prerequisites() {
    log "${YELLOW}Checking prerequisites...${NC}"
    if [ ! -d "${OPENVPN_WEBUI_DIR}" ]; then
        log "${RED}Error: ${OPENVPN_WEBUI_DIR} directory does not exist${NC}"
        exit 1
    fi
    if [ ! -f "${OPENVPN_WEBUI_DIR}/bin/webui.py" ]; then
        log "${RED}Error: ${OPENVPN_WEBUI_DIR}/bin/webui.py not found${NC}"
        exit 1
    fi
    if [ ! -f "${OPENVPN_WEBUI_DIR}/config/.env" ]; then
        log "${RED}Error: ${OPENVPN_WEBUI_DIR}/config/.env not found${NC}"
        exit 1
    fi
}

# Main function
main() {
    log "${GREEN}Starting deployment of openvpn-webui...${NC}"

    # Check if running as root or with sudo
    if [ "$EUID" -ne 0 ]; then
        log "${RED}Error: This script must be run as root or with sudo${NC}"
        exit 1
    fi

    # Check prerequisites
    check_prerequisites

    # Detect distribution
    detect_distro

    # Install Python and pip
    install_python

    # Install Python modules
    install_python_modules

    # Create systemd service
    create_systemd_service

    log "${GREEN}Deployment completed successfully!${NC}"
    log "${GREEN}OpenVPN WebUI is running as a systemd service: ${SERVICE_NAME}${NC}"
    log "${GREEN}You can check the status with: sudo systemctl status ${SERVICE_NAME}${NC}"
}

# Run main function
main