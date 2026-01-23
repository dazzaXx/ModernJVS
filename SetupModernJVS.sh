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
	
	print_info "Building ModernJVS..."
	
	# Use subshell to avoid changing directory in parent script
	if ! (cd "$repo_dir" && make && sudo make install); then
		print_error "Build or installation failed"
		exit 1
	fi
	
	print_success "ModernJVS installed successfully!"
}

# Main function
main() {
	print_info "=== ModernJVS Setup Script ==="
	
	check_sudo
	update_package_lists
	install_dependencies
	setup_modernjvs
	
	print_success "=== Setup completed successfully! ==="
	print_info "You can now run ModernJVS. Check the README for usage instructions."
}

# Run main function
main