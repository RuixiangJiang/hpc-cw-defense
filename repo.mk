# Global Makefile configuration for hpc-cw-defense.
# Keep only project-wide settings here.

REPO_ROOT ?= $(abspath .)

THIRD_PARTY_DIR := $(REPO_ROOT)/third_party

CHIPWHISPERER_ROOT := $(THIRD_PARTY_DIR)/chipwhisperer
CW_FIRMWARE_DIR := $(CHIPWHISPERER_ROOT)/firmware/mcu
FIRMWAREPATH := $(CW_FIRMWARE_DIR)

# pqm4 is the normalized local name for pqm4 Round3.
PQM4_ROOT := $(THIRD_PARTY_DIR)/pqm4

DEFAULT_PLATFORM := CWLITEARM
DEFAULT_SS_VER := SS_VER_2_1
DEFAULT_CRYPTO_TARGET := NONE
