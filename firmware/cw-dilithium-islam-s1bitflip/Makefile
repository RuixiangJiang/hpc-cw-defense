# ---------------------------------------------------------------------
# ChipWhisperer firmware for:
#   Islam et al., "Signature Correction Attack on Dilithium Signature Scheme"
#
# Fault model:
#   Rowhammer-style data corruption of the packed secret-key component s1.
#
# Simulation rule:
#   1. Generate an ordinary Dilithium2 keypair.
#   2. Before signing starts, flip one selected bit inside the in-memory packed
#      s1 region of sk.
#   3. Run the original crypto_sign_signature(...) function unchanged.
#   4. Restore the flipped bit after signing if requested.
#
# No source-level modification is made to sign.c, the signing loop, or
# z-generation.
# ---------------------------------------------------------------------

TARGET ?= cw-dilithium-islam-s1bitflip-singlebin
PLATFORM ?= CWLITEARM
SS_VER ?= SS_VER_2_1
CRYPTO_TARGET = NONE
OPT ?= 3

APP_SRC ?= simpleserial-dilithium-islam.c
SRC = $(APP_SRC)

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
THIS_DIR := $(dir $(abspath $(THIS_MAKEFILE)))
REPO_ROOT := $(abspath $(THIS_DIR)/../..)

include $(REPO_ROOT)/repo.mk

DILITHIUM_NAME ?= dilithium2
DILITHIUM_IMPL ?= m4f

DILITHIUM_SIGN_ROOT := $(PQM4_ROOT)/crypto_sign
DILITHIUM_DIR := $(DILITHIUM_SIGN_ROOT)/$(DILITHIUM_NAME)/$(DILITHIUM_IMPL)

PQM4_COMMON := $(PQM4_ROOT)/common
MUPQ_COMMON := $(PQM4_ROOT)/mupq/common

EXTRAINCDIRS += $(DILITHIUM_DIR)
EXTRAINCDIRS += $(PQM4_COMMON)
EXTRAINCDIRS += $(MUPQ_COMMON)

DILITHIUM_C_FULL := $(shell find -L $(DILITHIUM_DIR) -maxdepth 1 -name '*.c' 2>/dev/null)
DILITHIUM_S_FULL := $(shell find -L $(DILITHIUM_DIR) -maxdepth 1 \( -name '*.S' -o -name '*.s' \) 2>/dev/null)

DILITHIUM_C_FULL := $(filter-out \
    %/test.c \
    %/speed.c \
    %/stack.c \
    %/main.c \
    %/PQCgenKAT_sign.c \
    %/nistkat.c, \
    $(DILITHIUM_C_FULL))

COMMON_C_FULL := \
    $(MUPQ_COMMON)/fips202.c \
    $(MUPQ_COMMON)/sp800-185.c \
    $(PQM4_COMMON)/randombytes.c

COMMON_S_FULL :=

ifneq ($(wildcard $(PQM4_COMMON)/keccakf1600.S),)
COMMON_S_FULL += $(PQM4_COMMON)/keccakf1600.S
else
COMMON_S_FULL += $(wildcard $(MUPQ_COMMON)/keccakf1600.S)
endif

DILITHIUM_C_FULL := $(wildcard $(DILITHIUM_C_FULL))
DILITHIUM_S_FULL := $(wildcard $(DILITHIUM_S_FULL))
COMMON_C_FULL := $(wildcard $(COMMON_C_FULL))
COMMON_S_FULL := $(wildcard $(COMMON_S_FULL))

ALL_C_FULL := $(DILITHIUM_C_FULL) $(COMMON_C_FULL)
ALL_S_FULL := $(DILITHIUM_S_FULL) $(COMMON_S_FULL)

VPATH += $(sort $(dir $(ALL_C_FULL) $(ALL_S_FULL)))

SRC += $(notdir $(ALL_C_FULL))
ASRC += $(notdir $(ALL_S_FULL))

CFLAGS += -Wno-unused-function
CFLAGS += -Wno-unused-variable
CFLAGS += -Wno-sign-compare
CFLAGS += -Wno-implicit-function-declaration
CFLAGS += $(EXTRA_CFLAGS)

.PHONY: print-dilithium-files
print-dilithium-files:
	@echo "REPO_ROOT        = $(REPO_ROOT)"
	@echo "FIRMWAREPATH     = $(FIRMWAREPATH)"
	@echo "PQM4_ROOT        = $(PQM4_ROOT)"
	@echo "DILITHIUM_DIR    = $(DILITHIUM_DIR)"
	@echo "APP_SRC          = $(APP_SRC)"
	@echo "VPATH            = $(VPATH)"
	@echo "SRC              = $(SRC)"
	@echo "ASRC             = $(ASRC)"
	@echo "EXTRAINCDIRS     = $(EXTRAINCDIRS)"
	@echo "EXTRA_CFLAGS     = $(EXTRA_CFLAGS)"

include $(FIRMWAREPATH)/simpleserial/Makefile.simpleserial
include $(FIRMWAREPATH)/Makefile.inc

FPU_FLAGS = -mfpu=fpv4-sp-d16 -mfloat-abi=softfp

CFLAGS  := $(filter-out -mfloat-abi=soft,$(CFLAGS)) $(FPU_FLAGS)
ASFLAGS := $(filter-out -mfloat-abi=soft,$(ASFLAGS)) $(FPU_FLAGS)
LDFLAGS := $(filter-out -mfloat-abi=soft,$(LDFLAGS)) $(FPU_FLAGS)
