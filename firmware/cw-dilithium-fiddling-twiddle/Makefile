# ---------------------------------------------------------------------
# ChipWhisperer firmware for:
#   Ravi et al., "Fiddling the Twiddle Constants"
#
# Fault model:
#   Data corruption of the twiddle pointer or loaded twiddle value consumed
#   by one NTT butterfly.
#
# Simulation rule:
#   - do not skip the NTT layer;
#   - do not skip the butterfly loop;
#   - execute normal prefix butterflies;
#   - execute one target butterfly with corrupted twiddle data;
#   - execute normal suffix butterflies.
#
# Runtime fault models:
#   0 = none
#   1 = pointer-corruption: redirect twiddle pointer before target butterfly
#   2 = value-corruption: replace loaded twiddle before butterfly uses it
# ---------------------------------------------------------------------

TARGET ?= cw-dilithium-fiddling-twiddle-singlebin
PLATFORM ?= CWLITEARM
SS_VER ?= SS_VER_2_1
CRYPTO_TARGET = NONE
OPT ?= 3

APP_SRC ?= simpleserial-dilithium-fiddling.c
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

.PHONY: print-fiddling-files
print-fiddling-files:
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
