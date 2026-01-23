#!/bin/bash
set -euo pipefail

# Disable Bluetooth Script for Raspberry Pi (not needed for Pi 5)
# This script disables internal Bluetooth and installs external USB Bluetooth packages
# Note: This is required for Pi models 1-4 to use USB Bluetooth adapters, but not for Pi 5

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

# Configuration file locations (check both possible paths)
readonly BOOTCONFIG_NEW="/boot/firmware/config.txt"
readonly BOOTCONFIG_OLD="/boot/config.txt"

# Required packages for USB Bluetooth
readonly PACKAGES=(
	"bluetooth"
	"bluez"
	"bluez-tools"
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

# Find the correct boot config file
find_boot_config() {
	if [ -f "$BOOTCONFIG_NEW" ]; then
		echo "$BOOTCONFIG_NEW"
	elif [ -f "$BOOTCONFIG_OLD" ]; then
		echo "$BOOTCONFIG_OLD"
	else
		return 1
	fi
	return 0
}

# Check if running with sudo
check_sudo() {
	if [ "$EUID" -ne 0 ]; then
		print_error "This script must be run with sudo privileges"
		print_info "Usage: sudo $0"
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
		if ! apt install -y "$package"; then
			print_error "Failed to install $package"
			return 1
		fi
		print_success "$package installed successfully!"
	fi
	return 0
}

# Disable internal Bluetooth module
disable_internal_bluetooth() {
	local bootconfig
	if ! bootconfig=$(find_boot_config); then
		print_error "Could not find boot config file at $BOOTCONFIG_NEW or $BOOTCONFIG_OLD"
		exit 1
	fi
	
	print_info "Using boot config: $bootconfig"
	
	if grep -q "dtoverlay=disable-bt" "$bootconfig"; then
		print_info "Internal Bluetooth module already disabled, skipping!"
		return 0
	else
		print_info "Disabling internal Bluetooth module..."
		if ! printf '\n# Disable internal Bluetooth to use USB Bluetooth adapter\ndtoverlay=disable-bt\n' >> "$bootconfig"; then
			print_error "Failed to modify boot config"
			exit 1
		fi
		print_success "Internal Bluetooth module disabled in config!"
		return 1  # Return 1 to indicate reboot is needed
	fi
}

# Install USB Bluetooth packages
install_bluetooth_packages() {
	print_info "Installing USB Bluetooth packages..."
	
	# Update package lists first
	print_info "Updating package lists..."
	if ! apt update; then
		print_error "Failed to update package lists"
		exit 1
	fi
	
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
	
	print_success "All Bluetooth packages installed successfully!"
}

# Main function
main() {
	local reboot_needed=0
	
	print_info "=== Raspberry Pi Internal Bluetooth Configuration Script ==="
	print_info "Note: This script is for Pi models 1-4. Not needed for Pi 5."
	
	check_sudo
	
	# Disable internal Bluetooth
	if ! disable_internal_bluetooth; then
		reboot_needed=1
	fi
	
	# Install USB Bluetooth packages
	install_bluetooth_packages
	
	# Prompt for reboot if needed
	if [ $reboot_needed -eq 1 ]; then
		print_success "Configuration completed successfully!"
		print_info "A reboot is required for the changes to take effect."
		read -t 30 -p "Do you want to reboot now? (y/n): " -n 1 -r || REPLY='n'
		echo
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			print_info "Rebooting..."
			reboot
		else
			print_info "Please reboot manually when ready: sudo reboot"
		fi
	else
		print_success "=== Configuration completed successfully! ==="
	fi
}

# Run main function
main
