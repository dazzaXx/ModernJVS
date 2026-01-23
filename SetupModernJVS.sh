#!/bin/bash
set -euo pipefail

# ModernJVS Setup Script
# This script installs dependencies and sets up ModernJVS

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

# Required packages
readonly PACKAGES=(
	"build-essential"
	"cmake"
	"git"
	"file"
	"libgpiod-dev"
	"pkg-config"
)

# Service name
readonly SERVICE_NAME="modernjvs.service"

# Print colored messages
print_error() {
	echo -e "${RED}ERROR: $1${NC}" >&2
}

print_success() {
	echo -e "${GREEN}$1${NC}"
}

print_info() {
	echo -e "${YELLOW}$1${NC}"
}

# Check if running as root (we need sudo for some commands)
check_sudo() {
	if ! command -v sudo &> /dev/null; then
		print_error "sudo is not available on this system"
		exit 1
	fi
}

# Install a package if not already installed
install_package() {
	local package="$1"
	
	if dpkg -s "$package" >/dev/null 2>&1; then
		print_info "$package already installed, skipping!"
	else
		print_info "$package NOT installed, installing now!"
		if ! sudo apt install -y "$package"; then
			print_error "Failed to install $package"
			return 1
		fi
		print_success "$package installed successfully!"
	fi
	return 0
}

# Update package lists
update_package_lists() {
	print_info "Updating package lists..."
	if ! sudo apt update; then
		print_error "Failed to update package lists"
		exit 1
	fi
}

# Install all required packages
install_dependencies() {
	print_info "Installing dependencies..."
	local failed=0
	
	for package in "${PACKAGES[@]}"; do
		if ! install_package "$package"; then
			failed=1
		fi
	done
	
	if [ $failed -eq 1 ]; then
		print_error "Some packages failed to install"
		exit 1
	fi
	
	print_success "All dependencies installed successfully!"
}

# Clone and build ModernJVS
setup_modernjvs() {
	local repo_dir="ModernJVS"
	local build_dir=""
	
	# Check if we're already in the ModernJVS git repository
	if git rev-parse --is-inside-work-tree &>/dev/null; then
		local remote_url
		# Suppress error if no remote exists (stderr redirect is for error handling, not user prompts)
		remote_url=$(git remote get-url origin 2>/dev/null || echo "")
		
		# Check if this is the ModernJVS repository (match exact repo name at end of URL)
		if [[ "$remote_url" == *"/ModernJVS" ]] || [[ "$remote_url" == *"/ModernJVS.git" ]]; then
			print_info "Already in ModernJVS repository, skipping clone..."
			build_dir="."
		fi
	fi
	
	# If not in ModernJVS repo, clone it
	if [ -z "$build_dir" ]; then
		# Check if directory already exists
		if [ -d "$repo_dir" ]; then
			print_error "Directory '$repo_dir' already exists. Please remove it or run this script from a different location."
			exit 1
		fi
		
		print_info "Cloning ModernJVS repository..."
		if ! git clone https://github.com/dazzaXx/ModernJVS.git; then
			print_error "Failed to clone repository"
			exit 1
		fi
		build_dir="$repo_dir"
	fi
	
	print_info "Building ModernJVS..."
	
	# Use subshell to avoid changing directory in parent script
	if ! (cd "$build_dir" && make && sudo make install); then
		print_error "Build or installation failed"
		exit 1
	fi
	
	print_success "ModernJVS installed successfully!"
}

# Check service status
check_service_status() {
	local is_enabled=false
	local is_active=false
	
	if systemctl is-enabled "$SERVICE_NAME" &>/dev/null; then
		is_enabled=true
	fi
	
	if systemctl is-active "$SERVICE_NAME" &>/dev/null; then
		is_active=true
	fi
	
	echo "$is_enabled:$is_active"
}

# Enable and start the service
enable_and_start_service() {
	print_info "Enabling and starting ModernJVS service..."
	
	if ! sudo systemctl enable "$SERVICE_NAME"; then
		print_error "Failed to enable ModernJVS service"
		return 1
	fi
	
	if ! sudo systemctl start "$SERVICE_NAME"; then
		print_error "Failed to start ModernJVS service"
		return 1
	fi
	
	print_success "ModernJVS service enabled and started successfully!"
	print_info "The service will now start automatically on boot."
	return 0
}

# Disable and stop the service
disable_and_stop_service() {
	print_info "Disabling and stopping ModernJVS service..."
	
	# Stop the service if it's running
	if systemctl is-active "$SERVICE_NAME" &>/dev/null; then
		if ! sudo systemctl stop "$SERVICE_NAME"; then
			print_error "Failed to stop ModernJVS service"
			return 1
		fi
	fi
	
	# Disable the service if it's enabled
	if systemctl is-enabled "$SERVICE_NAME" &>/dev/null; then
		if ! sudo systemctl disable "$SERVICE_NAME"; then
			print_error "Failed to disable ModernJVS service"
			return 1
		fi
	fi
	
	print_success "ModernJVS service disabled and stopped successfully!"
	print_info "The service will no longer start automatically on boot."
	return 0
}

# Manage service (interactive menu)
manage_service() {
	local status
	status=$(check_service_status)
	local is_enabled="${status%%:*}"
	local is_active="${status##*:}"
	
	echo ""
	print_info "=== ModernJVS Service Management ==="
	echo ""
	
	# Display current status
	if [ "$is_enabled" = "true" ]; then
		print_success "Service is currently ENABLED (will start on boot)"
	else
		print_info "Service is currently DISABLED (will not start on boot)"
	fi
	
	if [ "$is_active" = "true" ]; then
		print_success "Service is currently ACTIVE (running)"
	else
		print_info "Service is currently INACTIVE (not running)"
	fi
	
	echo ""
	echo "What would you like to do?"
	echo "1) Enable and start the service (auto-start on boot)"
	echo "2) Disable and stop the service"
	echo "3) Skip service management"
	echo ""
	
	read -r -p "Enter your choice (1-3): " choice
	
	case $choice in
		1)
			enable_and_start_service
			;;
		2)
			disable_and_stop_service
			;;
		3)
			print_info "Skipping service management."
			;;
		*)
			print_error "Invalid choice. Skipping service management."
			;;
	esac
}

# Main function
main() {
	print_info "=== ModernJVS Setup Script ==="
	
	check_sudo
	update_package_lists
	install_dependencies
	setup_modernjvs
	manage_service
	
	print_success "=== Setup completed successfully! ==="
	print_info "You can now run ModernJVS. Check the README for usage instructions."
}

# Run main function
main