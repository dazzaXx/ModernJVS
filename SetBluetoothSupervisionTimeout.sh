#!/bin/bash
set -euo pipefail

# Set Bluetooth Supervision Timeout Script
# This script sets the Bluetooth link supervision timeout to 3 seconds for all currently
# connected Bluetooth devices (both BR/EDR and LE). A shorter supervision timeout allows
# faster detection of disconnected devices (e.g. Wiimotes), reducing lag when a controller
# drops connection.
# Note: Re-run this script after pairing new Bluetooth devices to apply the timeout.

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

# Supervision timeout for BR/EDR connections in Bluetooth slots (1 slot = 0.625 ms)
# 3 seconds = 3000 ms / 0.625 ms = 4800 slots
readonly SUPERVISION_TIMEOUT_BREDR=4800

# Supervision timeout for LE connections in units of 10 ms
# 3 seconds = 3000 ms / 10 ms = 300 units
readonly SUPERVISION_TIMEOUT_LE=300

# LE connection interval parameters (units of 1.25 ms) used with hcitool lecup.
# These are low-latency defaults suitable for gaming controllers.
# 6 * 1.25 ms = 7.5 ms (minimum interval), 12 * 1.25 ms = 15 ms (maximum interval)
readonly LE_INTERVAL_MIN=6
readonly LE_INTERVAL_MAX=12
readonly LE_LATENCY=0

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

# Set the supervision timeout for a single BR/EDR (ACL) connection handle
set_supervision_timeout_bredr() {
	local handle="$1"
	local address="$2"

	if hcitool lsup "$handle" "$SUPERVISION_TIMEOUT_BREDR" >/dev/null 2>&1; then
		print_success "Set supervision timeout to 3 seconds for $address (handle $handle) [BR/EDR]"
		return 0
	else
		print_error "Failed to set supervision timeout for $address (handle $handle) [BR/EDR]"
		return 1
	fi
}

# Set the supervision timeout for a single LE connection handle
set_supervision_timeout_le() {
	local handle="$1"
	local address="$2"

	if hcitool lecup "$handle" "$LE_INTERVAL_MIN" "$LE_INTERVAL_MAX" "$LE_LATENCY" "$SUPERVISION_TIMEOUT_LE" >/dev/null 2>&1; then
		print_success "Set supervision timeout to 3 seconds for $address (handle $handle) [LE]"
		return 0
	else
		print_error "Failed to set supervision timeout for $address (handle $handle) [LE]"
		return 1
	fi
}

# Iterate over all active ACL and LE connections and apply the timeout
set_all_supervision_timeouts() {
	print_info "Scanning for active Bluetooth connections..."

	# hcitool con output lines look like:
	#   < ACL XX:XX:XX:XX:XX:XX handle N state 1 lm MASTER  (BR/EDR)
	#   < LE  XX:XX:XX:XX:XX:XX handle N state 1 lm MASTER  (Bluetooth LE)
	local connections
	connections=$(hcitool con 2>/dev/null | awk '/handle/ {print $2, $3, $5}')

	if [ -z "$connections" ]; then
		print_info "No active Bluetooth connections found."
		print_info "Connect your Bluetooth devices and run this script again."
		return 0
	fi

	local failed=0
	local count=0

	while IFS=' ' read -r type address handle; do
		if [ -n "$handle" ]; then
			case "$type" in
				ACL)
					set_supervision_timeout_bredr "$handle" "$address" || failed=1
					count=$((count + 1))
					;;
				LE)
					set_supervision_timeout_le "$handle" "$address" || failed=1
					count=$((count + 1))
					;;
				*)
					print_info "Skipping unknown connection type '$type' for $address (handle $handle)"
					;;
			esac
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
	print_info "Target timeout: 3 seconds (BR/EDR: $SUPERVISION_TIMEOUT_BREDR slots @ 0.625 ms, LE: $SUPERVISION_TIMEOUT_LE units @ 10 ms)"

	check_sudo
	check_dependencies
	set_all_supervision_timeouts

	print_success "=== Supervision timeout configuration completed! ==="
}

# Run main function
main
