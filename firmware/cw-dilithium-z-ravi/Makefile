# ---------------------------------------------------------------------
# ChipWhisperer Ravi z-generation kernel firmware
#
# This firmware intentionally does NOT run the full Dilithium keypair/sign
# pipeline on CWLITEARM/STM32F3. The full Dilithium2/m4f signing function has
# large stack workspaces and can overrun the small STM32F3 SRAM. Instead, this
# target exercises the exact final z-generation primitive:
#
#     z = c*s1 + y
#
# using deterministic in-memory polyvecl test vectors and the same
# prefix-target-suffix fault simulation used for the paper experiment.
# ---------------------------------------------------------------------

TARGET ?= cw-dilithium-z-ravi-singlebin
PLATFORM ?= CWLITEARM
SS_VER ?= SS_VER_2_1
CRYPTO_TARGET = NONE
OPT ?= 3

APP_SRC ?= simpleserial-dilithium-z-ravi.c
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

CFLAGS += -DCW_TRIGGER_RAVI_SIGN=0
CFLAGS += -Wno-unused-function
CFLAGS += -Wno-unused-variable
CFLAGS += -Wno-sign-compare
CFLAGS += $(EXTRA_CFLAGS)

.PHONY: print-dilithium-files
print-dilithium-files:
	@echo "mode = z-generation-kernel"
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

