.PHONY: default install install-no-webui enable-services clean

BUILD = build

# Set WEBUI=OFF to exclude the WebUI from the installation.
# Example: make install WEBUI=OFF
WEBUI ?= ON

# Set ENABLE_SERVICES=OFF to skip automatically enabling and starting the
# systemd services after installation.
# Example: make install ENABLE_SERVICES=OFF
ENABLE_SERVICES ?= ON

SERVICE_NAME       = modernjvs
WEBUI_SERVICE_NAME = modernjvs-webui

SERVICES_MSG = $(if $(filter ON,$(ENABLE_SERVICES)),enabled (use ENABLE_SERVICES=OFF to skip),disabled)

default: $(BUILD)/Makefile
	@cd $(BUILD) && $(MAKE) --no-print-directory

# Always reconfigure cmake with the current WEBUI flag so that switching
# between WEBUI=ON and WEBUI=OFF is safe even with an existing build directory.
install:
	@mkdir -p $(BUILD)
	@cd $(BUILD) && cmake .. -DENABLE_WEBUI=$(WEBUI)
	@cd $(BUILD) && $(MAKE) --no-print-directory
	@echo "-- Services: $(SERVICES_MSG)"
	@cd $(BUILD) && cpack
	@sudo dpkg --install $(BUILD)/*.deb
ifeq ($(ENABLE_SERVICES),ON)
ifeq ($(WEBUI),ON)
	@sudo systemctl enable --now $(SERVICE_NAME) $(WEBUI_SERVICE_NAME)
else
	@sudo systemctl enable --now $(SERVICE_NAME)
endif
endif

# Convenience target that builds and installs without the WebUI.
# Services are still enabled by default; pass ENABLE_SERVICES=OFF to skip.
install-no-webui:
	@mkdir -p $(BUILD)
	@cd $(BUILD) && cmake .. -DENABLE_WEBUI=OFF
	@cd $(BUILD) && $(MAKE) --no-print-directory
	@echo "-- Services: $(SERVICES_MSG)"
	@cd $(BUILD) && cpack
	@sudo dpkg --install $(BUILD)/*.deb
ifeq ($(ENABLE_SERVICES),ON)
	@sudo systemctl enable --now $(SERVICE_NAME)
endif

clean:
	@rm -rf $(BUILD)

# Manually enable and immediately start services.
# Only enables modernjvs-webui if its service file has been installed.
# Useful if ENABLE_SERVICES=OFF was used during installation.
enable-services:
	@sudo systemctl enable --now $(SERVICE_NAME)
	@test -f /etc/systemd/system/$(WEBUI_SERVICE_NAME).service && \
		sudo systemctl enable --now $(WEBUI_SERVICE_NAME) || true

$(BUILD)/Makefile:
	@mkdir -p $(BUILD)
	@cd $(BUILD) && cmake .. -DENABLE_WEBUI=$(WEBUI)
