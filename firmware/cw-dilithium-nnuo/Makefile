# ---------------------------------------------------------------------
# ChipWhisperer firmware for Ravi et al., "Number Not Used Once"
#
# This target is a SRAM-safe Dilithium nonce/domain-separation sampling
# kernel. It does not run full Dilithium signing. It exercises the semantic
# fault:
#
#   the second sampling call receives a stale nonce/domain-separation value
#   instead of the updated one, while the sampler itself runs normally.
#
# Baseline and attack use one firmware binary. Runtime mode is configured by
# SimpleSerial command F.
# ---------------------------------------------------------------------

TARGET ?= cw-dilithium-nnuo-singlebin
PLATFORM ?= CWLITEARM
SS_VER ?= SS_VER_2_1
CRYPTO_TARGET = NONE
OPT ?= 3

APP_SRC ?= simpleserial-dilithium-nnuo.c
SRC = $(APP_SRC)

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
THIS_DIR := $(dir $(abspath $(THIS_MAKEFILE)))
REPO_ROOT := $(abspath $(THIS_DIR)/../..)

include $(REPO_ROOT)/repo.mk

DILITHIUM_DIR := $(PQM4_ROOT)/crypto_sign/dilithium2/m4f
PQM4_COMMON := $(PQM4_ROOT)/common
MUPQ_COMMON := $(PQM4_ROOT)/mupq/common

EXTRAINCDIRS += $(DILITHIUM_DIR)
EXTRAINCDIRS += $(PQM4_COMMON)
EXTRAINCDIRS += $(MUPQ_COMMON)

CFLAGS += -Wno-unused-function
CFLAGS += -Wno-unused-variable
CFLAGS += -Wno-sign-compare
CFLAGS += $(EXTRA_CFLAGS)

.PHONY: print-nnuo-files
print-nnuo-files:
	@echo "mode = nnuo-sampling-kernel"
	@echo "REPO_ROOT = $(REPO_ROOT)"
	@echo "FIRMWAREPATH = $(FIRMWAREPATH)"
	@echo "PQM4_ROOT = $(PQM4_ROOT)"
	@echo "DILITHIUM_DIR = $(DILITHIUM_DIR)"
	@echo "SRC = $(SRC)"
	@echo "ASRC = $(ASRC)"
	@echo "EXTRAINCDIRS = $(EXTRAINCDIRS)"
	@echo "EXTRA_CFLAGS = $(EXTRA_CFLAGS)"

include $(FIRMWAREPATH)/simpleserial/Makefile.simpleserial
include $(FIRMWAREPATH)/Makefile.inc

FPU_FLAGS = -mfpu=fpv4-sp-d16 -mfloat-abi=softfp
CFLAGS := $(filter-out -mfloat-abi=soft,$(CFLAGS)) $(FPU_FLAGS)
ASFLAGS := $(filter-out -mfloat-abi=soft,$(ASFLAGS)) $(FPU_FLAGS)
LDFLAGS := $(filter-out -mfloat-abi=soft,$(LDFLAGS)) $(FPU_FLAGS)
