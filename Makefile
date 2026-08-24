BUILD_DIR := build
SRC_DIR := src

COMMON_FLAGS := -std=c99 -Wall -Wextra -Werror -ffunction-sections -fdata-sections
LEXRA_ROOT ?= /mnt/n300-rsdk/rsdk-4.6.4-5281-EB-3.10-0.9.33-m32ub-20141001
LEXRA_CC := $(LEXRA_ROOT)/bin/mips-linux-gcc
LEXRA_STRIP := $(LEXRA_ROOT)/bin/mips-linux-strip
OPENSSL_HEADERS ?= /tmp/n300vpn-openssl/openssl-1.0.2t/include
OPENSSL_ROOT ?= $(CURDIR)/build/openssl111w-reality

.PHONY: lexra clean

lexra: $(BUILD_DIR)/n300vless-lexra

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/n300vless-lexra: $(SRC_DIR)/n300vless.c | $(BUILD_DIR)
	STAGING_DIR=/tmp/n300vpn-staging $(LEXRA_CC) $(COMMON_FLAGS) -Os -march=5281 \
		-I$(OPENSSL_ROOT)/include $< \
		-Wl,--gc-sections $(OPENSSL_ROOT)/lib/libssl.a $(OPENSSL_ROOT)/lib/libcrypto.a \
		-pthread -ldl -lgcc_eh -o $@
	$(LEXRA_STRIP) $@

clean:
	rm -f $(BUILD_DIR)/n300vless-lexra
