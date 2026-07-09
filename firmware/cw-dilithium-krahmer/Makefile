# ---------------------------------------------------------------------
# ChipWhisperer firmware for:
#   Krahmer et al., "Correction Fault Attacks on Randomized Dilithium"
#   skipping-correction variant
#
# Fault model:
#   A local correction term in a randomized Dilithium-like signing computation
#   is omitted for one target coefficient.
#
# Simulation rule:
#   - do not skip the coefficient loop;
#   - do not skip the signing phase around the correction;
#   - normal prefix coefficients use the normal correction primitive;
#   - one target coefficient uses the faulted primitive that omits correction;
#   - normal suffix coefficients use the normal correction primitive.
#
# Target-window rule:
#   The measured primitive contains either the normal correction or the
#   correction-skip operation. Runtime dispatch is outside the measured target
#   primitive.
# ---------------------------------------------------------------------

TARGET ?= cw-dilithium-krahmer-skipcorr-singlebin
PLATFORM ?= CWLITEARM
SS_VER ?= SS_VER_2_1
CRYPTO_TARGET = NONE
OPT ?= 3

APP_SRC ?= simpleserial-dilithium-krahmer.c
SRC = $(APP_SRC)

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
THIS_DIR := $(dir $(abspath $(THIS_MAKEFILE)))
REPO_ROOT := $(abspath $(THIS_DIR)/../..)

include $(REPO_ROOT)/repo.mk

DILITHIUM_NAME ?= dilithium2
DILITHIUM_IMPL ?= m4f
DILITHIUM_DIR := $(PQM4_ROOT)/crypto_sign/$(DILITHIUM_NAME)/$(DILITHIUM_IMPL)

EXTRAINCDIRS += $(DILITHIUM_DIR)
EXTRAINCDIRS += $(PQM4_ROOT)/common
EXTRAINCDIRS += $(PQM4_ROOT)/mupq/common

CFLAGS += -Wno-unused-function
CFLAGS += -Wno-unused-variable
CFLAGS += -Wno-sign-compare
CFLAGS += -Wno-implicit-function-declaration
CFLAGS += $(EXTRA_CFLAGS)

.PHONY: print-krahmer-files
print-krahmer-files:
	@echo "REPO_ROOT    = $(REPO_ROOT)"
	@echo "FIRMWAREPATH = $(FIRMWAREPATH)"
	@echo "PQM4_ROOT    = $(PQM4_ROOT)"
	@echo "DILITHIUM_DIR= $(DILITHIUM_DIR)"
	@echo "SRC          = $(SRC)"
	@echo "EXTRAINCDIRS = $(EXTRAINCDIRS)"
	@echo "EXTRA_CFLAGS = $(EXTRA_CFLAGS)"

include $(FIRMWAREPATH)/simpleserial/Makefile.simpleserial
include $(FIRMWAREPATH)/Makefile.inc

FPU_FLAGS = -mfpu=fpv4-sp-d16 -mfloat-abi=softfp
CFLAGS  := $(filter-out -mfloat-abi=soft,$(CFLAGS)) $(FPU_FLAGS)
ASFLAGS := $(filter-out -mfloat-abi=soft,$(ASFLAGS)) $(FPU_FLAGS)
LDFLAGS := $(filter-out -mfloat-abi=soft,$(LDFLAGS)) $(FPU_FLAGS)
