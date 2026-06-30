# ---------------------------------------------------------------------
# ChipWhisperer firmware:
#   Kyber512-90s + CWLITEARM_STM32F3 + source-level decoder skip
# ---------------------------------------------------------------------

TARGET = cw-kyber51290s-decoder-skip

PLATFORM ?= CWLITEARM
SS_VER ?= SS_VER_2_1
CRYPTO_TARGET = NONE
OPT ?= 3

# ---------------------------------------------------------------------
# Locate repository root and experiment config
# ---------------------------------------------------------------------

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
THIS_MAKEFILE_DIR := $(dir $(abspath $(THIS_MAKEFILE)))
REPO_ROOT := $(abspath $(THIS_MAKEFILE_DIR)/../..)
APP_DIR := $(THIS_MAKEFILE_DIR)

include $(REPO_ROOT)/repo.mk
include $(REPO_ROOT)/scripts/Fault_Attacks_on_CCA-secure_Lattice_KEMs/exp.mk

# ---------------------------------------------------------------------
# Local app sources
# ---------------------------------------------------------------------

SRC = main.c
SRC += randombytes.c

# ---------------------------------------------------------------------
# Source discovery
# ---------------------------------------------------------------------
#
# Important:
# Do NOT put absolute paths directly into SRC.
# Use:
#   full-path discovery -> VPATH -> basename into SRC / ASRC
#
# This avoids object paths like:
#   objdir-CWLITEARM//home/ruixiang/.../kem.o
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

COMMON_C_FULL :=
COMMON_S_FULL :=

# Kyber-90s common C dependencies.
COMMON_C_FULL += $(wildcard $(PQM4_COMMON_DIR)/aes.c)
COMMON_C_FULL += $(wildcard $(PQM4_COMMON_DIR)/aes-publicinputs.c)
COMMON_C_FULL += $(wildcard $(PQM4_COMMON_DIR)/crypto_hashblocks_sha512.c)

COMMON_C_FULL += $(wildcard $(MUPQ_COMMON_DIR)/sha2.c)
COMMON_C_FULL += $(wildcard $(MUPQ_COMMON_DIR)/fips202.c)
COMMON_C_FULL += $(wildcard $(MUPQ_COMMON_DIR)/sp800-185.c)

# Common assembly dependencies.
# Use wildcard so missing files are simply not added.
COMMON_S_FULL += $(wildcard $(PQM4_COMMON_DIR)/aes-encrypt.S)
COMMON_S_FULL += $(wildcard $(PQM4_COMMON_DIR)/aes-keyschedule.S)
COMMON_S_FULL += $(wildcard $(PQM4_COMMON_DIR)/crypto_hashblocks_sha512_inner32.s)
COMMON_S_FULL += $(wildcard $(PQM4_COMMON_DIR)/keccakf1600.S)
COMMON_S_FULL += $(wildcard $(MUPQ_COMMON_DIR)/keccakf1600.S)

# Some pqm4 Round3 layouts place the frombytes_mul assembly helpers
# in a Kyber parameter-set directory different from KYBER_DIR.
# Discover the exact provider files by symbol name.
KYBER_EXTRA_ASM_FULL := $(shell \
	grep -Rsl \
		-e 'frombytes_mul_asm_16_32' \
		-e 'frombytes_mul_asm_acc_32_16' \
		$(KYBER_INC_DIRS) 2>/dev/null | grep -E '\.(S|s)$$' || true)

# crypto_hashblocks_sha512.c calls crypto_hashblocks_sha512_m4nofpu_inner.
# Different pqm4 Round3 checkouts use different filenames for this implementation.
SHA512_INNER_ASM_FULL := $(shell \
	grep -Rsl \
		-e 'crypto_hashblocks_sha512_m4nofpu_inner' \
		$(PQM4_COMMON_DIR) $(MUPQ_COMMON_DIR) 2>/dev/null | grep -E '\.(S|s)$$' || true)

KYBER_S_FULL += $(KYBER_EXTRA_ASM_FULL)
COMMON_S_FULL += $(SHA512_INNER_ASM_FULL)

# Avoid accidentally compiling aes-publicinputs.S twice if it is handled
# by the custom rule at the bottom of this Makefile.
COMMON_S_FULL := $(filter-out %/aes-publicinputs.S,$(COMMON_S_FULL))

ALL_C_FULL := $(sort $(KYBER_C_FULL) $(COMMON_C_FULL))
ALL_S_FULL := $(sort $(KYBER_S_FULL) $(COMMON_S_FULL))

# VPATH lets Make find basenames such as kem.c, poly.c, poly_asm.S.
VPATH += $(APP_DIR)
VPATH += $(KYBER_INC_DIRS)
VPATH += $(sort $(dir $(ALL_C_FULL) $(ALL_S_FULL)))

# Only basenames go into SRC/ASRC.
SRC  += $(notdir $(ALL_C_FULL))
ASRC += $(notdir $(ALL_S_FULL))

# ---------------------------------------------------------------------
# Include paths
# ---------------------------------------------------------------------

EXTRAINCDIRS += $(APP_DIR)
EXTRAINCDIRS += $(KYBER_INC_DIRS)
EXTRAINCDIRS += $(PQM4_COMMON_DIR)
EXTRAINCDIRS += $(MUPQ_COMMON_DIR)

CFLAGS += -I$(APP_DIR)
CFLAGS += $(addprefix -I,$(KYBER_INC_DIRS))
CFLAGS += -I$(PQM4_COMMON_DIR)
CFLAGS += -I$(MUPQ_COMMON_DIR)

# ---------------------------------------------------------------------
# Experiment flags
# ---------------------------------------------------------------------

EXTRA_CFLAGS ?= -DATTACK_DECODER_SKIP_QHALF=0

CFLAGS += $(EXTRA_CFLAGS)
CFLAGS += -fno-common

# Optional: useful when debugging file discovery.
print-kyber-files:
	@echo "REPO_ROOT        = $(REPO_ROOT)"
	@echo "APP_DIR          = $(APP_DIR)"
	@echo "KYBER_INC_DIRS   = $(KYBER_INC_DIRS)"
	@echo "KYBER_DIR        = $(KYBER_DIR)"
	@echo "PQM4_COMMON_DIR  = $(PQM4_COMMON_DIR)"
	@echo "MUPQ_COMMON_DIR  = $(MUPQ_COMMON_DIR)"
	@echo "VPATH            = $(VPATH)"
	@echo "SRC              = $(SRC)"
	@echo "ASRC             = $(ASRC)"
	@echo "EXTRAINCDIRS     = $(EXTRAINCDIRS)"
	@echo "CFLAGS           = $(CFLAGS)"

# ---------------------------------------------------------------------
# ChipWhisperer build system
# ---------------------------------------------------------------------

include $(FIRMWAREPATH)/simpleserial/Makefile.simpleserial
include $(FIRMWAREPATH)/Makefile.inc

# ---------------------------------------------------------------------
# Match the previously working pqm4/Cortex-M4 build flags
# ---------------------------------------------------------------------

FPU_FLAGS = -mfpu=fpv4-sp-d16 -mfloat-abi=softfp

CFLAGS  := $(filter-out -mfloat-abi=soft,$(CFLAGS)) $(FPU_FLAGS)
ASFLAGS := $(filter-out -mfloat-abi=soft,$(ASFLAGS)) $(FPU_FLAGS)
LDFLAGS := $(filter-out -mfloat-abi=soft,$(LDFLAGS)) $(FPU_FLAGS)

# ---------------------------------------------------------------------
# Optional custom assembly object for aes-publicinputs.S
# ---------------------------------------------------------------------
#
# Some pqm4 Round3 layouts include both:
#   aes-publicinputs.c
#   aes-publicinputs.S
#
# Building both through normal basename rules can collide. If the .S file
# exists, build it as a separately named object.
# ---------------------------------------------------------------------

PQM4_AES_PUBLICINPUTS_ASM := $(PQM4_COMMON_DIR)/aes-publicinputs.S
PQM4_AES_PUBLICINPUTS_ASM_OBJ := objdir-$(PLATFORM)/aes_publicinputs_asm_pqm4.o

ifneq ($(wildcard $(PQM4_AES_PUBLICINPUTS_ASM)),)
OBJS += $(PQM4_AES_PUBLICINPUTS_ASM_OBJ)

$(TARGET)-$(PLATFORM).elf: $(PQM4_AES_PUBLICINPUTS_ASM_OBJ)

$(PQM4_AES_PUBLICINPUTS_ASM_OBJ): $(PQM4_AES_PUBLICINPUTS_ASM)
	@mkdir -p $(dir $@)
	@echo "Assembling custom PQM4 AES publicinputs object: $<"
	$(CC) -c -mcpu=cortex-m4 -I. -x assembler-with-cpp -mthumb $(FPU_FLAGS) -fmessage-length=0 -ffunction-sections -DF_CPU=$(F_CPU) $(addprefix -I,$(EXTRAINCDIRS)) $< -o $@
endif
