# ---------------------------------------------------------------------
# ChipWhisperer firmware for Delvaux, "Roulette"
#
# This is a SRAM-safe masked-intermediate kernel. It does not require a
# masked Kyber implementation in pqm4. It models Roulette as faults on one
# masked intermediate in a Kyber-like re-encryption / decoding pipeline.
#
# Runtime fault models:
#   0 = none
#   1 = instruction-skip: remove the target masked local operation
#   2 = set-to-constant
#   3 = random fault
#   4 = bit-flip
#
# The target is inside a coefficient loop and is implemented by a
# prefix-target-suffix structure.
# ---------------------------------------------------------------------

TARGET ?= cw-kyber51290s-roulette-singlebin
PLATFORM ?= CWLITEARM
SS_VER ?= SS_VER_2_1
CRYPTO_TARGET = NONE
OPT ?= 3

APP_SRC ?= simpleserial-kyber-roulette.c
SRC = $(APP_SRC)

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
THIS_DIR := $(dir $(abspath $(THIS_MAKEFILE)))
REPO_ROOT := $(abspath $(THIS_DIR)/../..)

include $(REPO_ROOT)/repo.mk

KYBER_NAME ?= kyber512-90s
KYBER_IMPL ?= m4fspeed

KYBER_DIR := $(PQM4_ROOT)/crypto_kem/$(KYBER_NAME)/$(KYBER_IMPL)

EXTRAINCDIRS += $(KYBER_DIR)
EXTRAINCDIRS += $(PQM4_ROOT)/common
EXTRAINCDIRS += $(PQM4_ROOT)/mupq/common

CFLAGS += -Wno-unused-function
CFLAGS += -Wno-unused-variable
CFLAGS += -Wno-sign-compare
CFLAGS += -Wno-implicit-function-declaration
CFLAGS += $(EXTRA_CFLAGS)

.PHONY: print-roulette-files
print-roulette-files:
	@echo "REPO_ROOT    = $(REPO_ROOT)"
	@echo "FIRMWAREPATH = $(FIRMWAREPATH)"
	@echo "PQM4_ROOT    = $(PQM4_ROOT)"
	@echo "KYBER_DIR    = $(KYBER_DIR)"
	@echo "SRC          = $(SRC)"
	@echo "EXTRAINCDIRS = $(EXTRAINCDIRS)"
	@echo "EXTRA_CFLAGS = $(EXTRA_CFLAGS)"

include $(FIRMWAREPATH)/simpleserial/Makefile.simpleserial
include $(FIRMWAREPATH)/Makefile.inc

FPU_FLAGS = -mfpu=fpv4-sp-d16 -mfloat-abi=softfp
CFLAGS  := $(filter-out -mfloat-abi=soft,$(CFLAGS)) $(FPU_FLAGS)
ASFLAGS := $(filter-out -mfloat-abi=soft,$(ASFLAGS)) $(FPU_FLAGS)
LDFLAGS := $(filter-out -mfloat-abi=soft,$(LDFLAGS)) $(FPU_FLAGS)
