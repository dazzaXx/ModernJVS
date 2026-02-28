#!/bin/bash
set -euo pipefail

# Set Bluetooth Supervision Timeout Script
# This script sets the Bluetooth link supervision timeout to 3 seconds for all currently
# connected Bluetooth devices. A shorter supervision timeout allows faster detection of
# disconnected devices (e.g. Wiimotes), reducing lag when a controller drops connection.
# Note: Re-run this script after pairing new Bluetooth devices to apply the timeout.

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

# Supervision timeout in Bluetooth slots (1 slot = 0.625 ms)
# 3 seconds = 3000 ms / 0.625 ms = 4800 slots
readonly SUPERVISION_TIMEOUT=4800

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

# Check if running with sudo
check_sudo() {
	if [ "$EUID" -ne 0 ]; then
		print_error "This script must be run with sudo privileges"
		print_info "Usage: sudo $0"
		exit 1
	fi
}

# Check that hcitool is available
check_dependencies() {
	if ! command -v hcitool >/dev/null 2>&1; then
		print_error "hcitool not found. Please install bluez: sudo apt install bluez"
		exit 1
	fi
}

# Set the supervision timeout for a single connection handle
set_supervision_timeout() {
	local handle="$1"
	local address="$2"

	if hcitool lsup "$handle" "$SUPERVISION_TIMEOUT" >/dev/null 2>&1; then
		print_success "Set supervision timeout to 3 seconds for $address (handle $handle)"
		return 0
	else
		print_error "Failed to set supervision timeout for $address (handle $handle)"
		return 1
	fi
}

# Iterate over all active ACL connections and apply the timeout
set_all_supervision_timeouts() {
	print_info "Scanning for active Bluetooth connections..."

	# hcitool con output lines look like:
	#   < ACL XX:XX:XX:XX:XX:XX handle N state 1 lm MASTER
	local connections
	connections=$(hcitool con 2>/dev/null | awk '/handle/ {print $3, $5}')

	if [ -z "$connections" ]; then
		print_info "No active Bluetooth connections found."
		print_info "Connect your Bluetooth devices and run this script again."
		return 0
	fi

	local failed=0
	local count=0

	while IFS=' ' read -r address handle; do
		if [ -n "$handle" ]; then
			set_supervision_timeout "$handle" "$address" || failed=1
			count=$((count + 1))
		fi
	done <<< "$connections"

	if [ "$failed" -eq 1 ]; then
		print_error "Some connections failed to update"
		exit 1
	fi

	print_success "Successfully updated supervision timeout for $count connection(s)"
}

# Main function
main() {
	print_info "=== Bluetooth Supervision Timeout Configuration Script ==="
	print_info "Target timeout: 3 seconds ($SUPERVISION_TIMEOUT Bluetooth slots)"

	check_sudo
	check_dependencies
	set_all_supervision_timeouts

	print_success "=== Supervision timeout configuration completed! ==="
}

# Run main function
main
