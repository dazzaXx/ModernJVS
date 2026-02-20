.PHONY: default install install-no-webui clean

BUILD = build

# Set WEBUI=OFF to exclude the WebUI from the installation.
# Example: make install WEBUI=OFF
WEBUI ?= ON

default: $(BUILD)/Makefile
	@cd $(BUILD) && $(MAKE) --no-print-directory

install: default
	@cd $(BUILD) && cpack
	@sudo dpkg --install $(BUILD)/*.deb

# Convenience target that builds and installs without the WebUI.
# Equivalent to: make install WEBUI=OFF
install-no-webui:
	@mkdir -p $(BUILD)
	@cd $(BUILD) && cmake .. -DENABLE_WEBUI=OFF
	@cd $(BUILD) && $(MAKE) --no-print-directory
	@cd $(BUILD) && cpack
	@sudo dpkg --install $(BUILD)/*.deb

clean:
	@rm -rf $(BUILD)

$(BUILD)/Makefile:
	@mkdir -p $(BUILD)
	@cd $(BUILD) && cmake .. -DENABLE_WEBUI=$(WEBUI)
