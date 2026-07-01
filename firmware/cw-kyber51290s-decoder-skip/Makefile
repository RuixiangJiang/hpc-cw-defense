# ---------------------------------------------------------------------
# ChipWhisperer Kyber512-90s decoder-skip firmware Makefile
#
# This Makefile intentionally follows the previously validated
# Makefile.kyberprobe style:
#   - explicit pqm4 source list
#   - VPATH + basenames only
#   - no NO_KYBER switch
#   - no experimental object discovery logic
#   - no target-specific ASFLAGS rules
#
# Expected app source:
#   simpleserial-kyberprobe.c
# ---------------------------------------------------------------------

TARGET ?= cw-kyber51290s-decoder-skip

PLATFORM ?= CWLITEARM
SS_VER ?= SS_VER_2_1
CRYPTO_TARGET = NONE
OPT ?= 3

APP_SRC ?= simpleserial-kyberprobe.c
SRC = $(APP_SRC)

# ---------------------------------------------------------------------
# Repository layout
# ---------------------------------------------------------------------

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
THIS_DIR := $(dir $(abspath $(THIS_MAKEFILE)))
REPO_ROOT := $(abspath $(THIS_DIR)/../..)

include $(REPO_ROOT)/repo.mk
include $(REPO_ROOT)/scripts/Fault_Attacks_on_CCA-secure_Lattice_KEMs/exp.mk

KYBER_NAME ?= kyber512-90s
KYBER_IMPL ?= m4fspeed

KYBER_KEM_ROOT := $(PQM4_ROOT)/crypto_kem
KYBER_DIR := $(KYBER_KEM_ROOT)/$(KYBER_NAME)/$(KYBER_IMPL)

PQM4_COMMON := $(PQM4_ROOT)/common
MUPQ_COMMON := $(PQM4_ROOT)/mupq/common

# ---------------------------------------------------------------------
# Include paths
# ---------------------------------------------------------------------

EXTRAINCDIRS += $(KYBER_DIR)

# These extra include dirs are needed by pqm4 m4fspeed assembly includes,
# e.g. matacc.i. Keep the same broad search style as the working
# Makefile.kyberprobe.
EXTRAINCDIRS += $(KYBER_KEM_ROOT)/kyber512-90s/$(KYBER_IMPL)
EXTRAINCDIRS += $(KYBER_KEM_ROOT)/kyber512/$(KYBER_IMPL)
EXTRAINCDIRS += $(KYBER_KEM_ROOT)/kyber768-90s/$(KYBER_IMPL)
EXTRAINCDIRS += $(KYBER_KEM_ROOT)/kyber768/$(KYBER_IMPL)

EXTRAINCDIRS += $(PQM4_COMMON)
EXTRAINCDIRS += $(MUPQ_COMMON)

# ---------------------------------------------------------------------
# Explicit pqm4 source list
# ---------------------------------------------------------------------
#
# Do not put full paths directly into SRC/ASRC.
# ChipWhisperer's Makefile expects object names like:
#
#   objdir-CWLITEARM/poly.o
#
# not:
#
#   objdir-CWLITEARM/home/.../poly.o
#
# Therefore we:
#   1. collect full paths in *_FULL variables
#   2. add their directories to VPATH
#   3. add only basenames to SRC/ASRC
# ---------------------------------------------------------------------

# ---------------------------------------------------------------------
# Kyber source discovery
# ---------------------------------------------------------------------
# Use the same style as the previously validated Makefile.kyberprobe:
# collect all implementation-local C and assembly files, then filter out
# test/benchmark entry points.
# This avoids missing implementation-specific asm helpers such as
# frombytes_mul_asm_*.
# ---------------------------------------------------------------------

KYBER_C_FULL := $(shell find -L $(KYBER_DIR) -maxdepth 1 -name '*.c' 2>/dev/null)

KYBER_S_FULL := $(shell find -L $(KYBER_DIR) -maxdepth 1 \( -name '*.S' -o -name '*.s' \) 2>/dev/null)

KYBER_C_FULL := $(filter-out \
    %/test.c \
    %/speed.c \
    %/stack.c \
    %/main.c \
    %/PQCgenKAT_kem.c \
    %/nistkat.c, \
    $(KYBER_C_FULL))

COMMON_C_FULL := \
    $(PQM4_COMMON)/aes.c \
    $(PQM4_COMMON)/aes-publicinputs.c \
    $(PQM4_COMMON)/crypto_hashblocks_sha512.c \
    $(MUPQ_COMMON)/sha2.c \
    $(MUPQ_COMMON)/fips202.c \
    $(MUPQ_COMMON)/sp800-185.c \
    $(PQM4_COMMON)/randombytes.c

COMMON_S_FULL := \
    $(PQM4_COMMON)/aes-encrypt.S \
    $(PQM4_COMMON)/aes-keyschedule.S \
    $(PQM4_COMMON)/crypto_hashblocks_sha512_inner32.s

# Prefer pqm4/common/keccakf1600.S if present; otherwise fall back to
# mupq/common/keccakf1600.S. Do not include both, because they have the
# same basename and would collide as keccakf1600.o.
ifneq ($(wildcard $(PQM4_COMMON)/keccakf1600.S),)
COMMON_S_FULL += $(PQM4_COMMON)/keccakf1600.S
else
COMMON_S_FULL += $(wildcard $(MUPQ_COMMON)/keccakf1600.S)
endif

# Drop files that do not exist in this checkout.
KYBER_C_FULL := $(wildcard $(KYBER_C_FULL))
KYBER_S_FULL := $(wildcard $(KYBER_S_FULL))
COMMON_C_FULL := $(wildcard $(COMMON_C_FULL))
COMMON_S_FULL := $(wildcard $(COMMON_S_FULL))

ALL_C_FULL := $(KYBER_C_FULL) $(COMMON_C_FULL)
ALL_S_FULL := $(KYBER_S_FULL) $(COMMON_S_FULL)

VPATH += $(sort $(dir $(ALL_C_FULL) $(ALL_S_FULL)))

SRC += $(notdir $(ALL_C_FULL))
ASRC += $(notdir $(ALL_S_FULL))

# ---------------------------------------------------------------------
# Experiment / warning flags
# ---------------------------------------------------------------------

CFLAGS += -DCW_TRIGGER_POLY_TOMSG
CFLAGS += -DKYBER_TRIGGER_INSIDE_DECODER=0
CFLAGS += -Wno-unused-function
CFLAGS += -Wno-unused-variable
CFLAGS += -Wno-sign-compare
CFLAGS += -Wno-implicit-function-declaration

# Build scripts can pass:
#   EXTRA_CFLAGS="-DATTACK_DECODER_SKIP_QHALF=0"
# or:
#   EXTRA_CFLAGS="-DATTACK_DECODER_SKIP_QHALF=1 -DATTACK_TARGET_COEFF=0"
CFLAGS += $(EXTRA_CFLAGS)

# ---------------------------------------------------------------------
# Debug helper
# ---------------------------------------------------------------------

.PHONY: print-kyber-files
print-kyber-files:
	@echo "REPO_ROOT        = $(REPO_ROOT)"
	@echo "FIRMWAREPATH     = $(FIRMWAREPATH)"
	@echo "PQM4_ROOT        = $(PQM4_ROOT)"
	@echo "KYBER_DIR        = $(KYBER_DIR)"
	@echo "PQM4_COMMON      = $(PQM4_COMMON)"
	@echo "MUPQ_COMMON      = $(MUPQ_COMMON)"
	@echo "APP_SRC          = $(APP_SRC)"
	@echo "VPATH            = $(VPATH)"
	@echo "SRC              = $(SRC)"
	@echo "ASRC             = $(ASRC)"
	@echo "EXTRAINCDIRS     = $(EXTRAINCDIRS)"
	@echo "EXTRA_CFLAGS     = $(EXTRA_CFLAGS)"

# ---------------------------------------------------------------------
# ChipWhisperer build system
# ---------------------------------------------------------------------

include $(FIRMWAREPATH)/simpleserial/Makefile.simpleserial
include $(FIRMWAREPATH)/Makefile.inc

# pqm4 m4fspeed assembly uses Cortex-M4F VFP registers as scratch
# registers. The previously working Makefile used these flags globally
# after including ChipWhisperer's Makefile.inc, so we preserve that known
# working behavior here.
FPU_FLAGS = -mfpu=fpv4-sp-d16 -mfloat-abi=softfp

CFLAGS  := $(filter-out -mfloat-abi=soft,$(CFLAGS)) $(FPU_FLAGS)
ASFLAGS := $(filter-out -mfloat-abi=soft,$(ASFLAGS)) $(FPU_FLAGS)
LDFLAGS := $(filter-out -mfloat-abi=soft,$(LDFLAGS)) $(FPU_FLAGS)

# ---------------------------------------------------------------------
# Build aes-publicinputs.S as a separate object
# ---------------------------------------------------------------------
#
# pqm4 has both:
#   aes-publicinputs.c
#   aes-publicinputs.S
#
# If both are added normally, they collide as aes-publicinputs.o.
# The tested Makefile.kyberprobe solved this by building the .S file as
# a custom object name. Keep that design.
# ---------------------------------------------------------------------

PQM4_AES_PUBLICINPUTS_ASM := $(PQM4_COMMON)/aes-publicinputs.S

ifneq ($(wildcard $(PQM4_AES_PUBLICINPUTS_ASM)),)
PQM4_AES_PUBLICINPUTS_ASM_OBJ := objdir-$(PLATFORM)/aes_publicinputs_asm_pqm4.o

OBJS += $(PQM4_AES_PUBLICINPUTS_ASM_OBJ)
$(TARGET)-$(PLATFORM).elf: $(PQM4_AES_PUBLICINPUTS_ASM_OBJ)

$(PQM4_AES_PUBLICINPUTS_ASM_OBJ): $(PQM4_AES_PUBLICINPUTS_ASM)
	@mkdir -p $(dir $@)
	@echo "Assembling custom PQM4 AES publicinputs object: $<"
	$(CC) -c -mcpu=cortex-m4 -I. -x assembler-with-cpp -mthumb $(FPU_FLAGS) -fmessage-length=0 -ffunction-sections -DF_CPU=$(F_CPU) $(addprefix -I,$(EXTRAINCDIRS)) $< -o $@
endif
