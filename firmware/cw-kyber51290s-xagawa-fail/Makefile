TARGET ?= cw-kyber51290s-xagawa-fail-singlebin
PLATFORM ?= CWLITEARM
SS_VER ?= SS_VER_2_1
CRYPTO_TARGET = NONE
OPT ?= 3

APP_SRC ?= simpleserial-kyber-xagawa.c
SRC = $(APP_SRC)

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
THIS_DIR := $(dir $(abspath $(THIS_MAKEFILE)))
REPO_ROOT := $(abspath $(THIS_DIR)/../..)

include $(REPO_ROOT)/repo.mk

KYBER_NAME ?= kyber512-90s
KYBER_IMPL ?= m4fspeed

KYBER_KEM_ROOT := $(PQM4_ROOT)/crypto_kem
KYBER_DIR := $(KYBER_KEM_ROOT)/$(KYBER_NAME)/$(KYBER_IMPL)

PQM4_COMMON := $(PQM4_ROOT)/common
MUPQ_COMMON := $(PQM4_ROOT)/mupq/common

EXTRAINCDIRS += $(KYBER_DIR)
EXTRAINCDIRS += $(KYBER_KEM_ROOT)/kyber512-90s/$(KYBER_IMPL)
EXTRAINCDIRS += $(KYBER_KEM_ROOT)/kyber512/$(KYBER_IMPL)
EXTRAINCDIRS += $(KYBER_KEM_ROOT)/kyber768-90s/$(KYBER_IMPL)
EXTRAINCDIRS += $(KYBER_KEM_ROOT)/kyber768/$(KYBER_IMPL)
EXTRAINCDIRS += $(PQM4_COMMON)
EXTRAINCDIRS += $(MUPQ_COMMON)

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

ifneq ($(wildcard $(PQM4_COMMON)/keccakf1600.S),)
COMMON_S_FULL += $(PQM4_COMMON)/keccakf1600.S
else
COMMON_S_FULL += $(wildcard $(MUPQ_COMMON)/keccakf1600.S)
endif

KYBER_C_FULL := $(wildcard $(KYBER_C_FULL))
KYBER_S_FULL := $(wildcard $(KYBER_S_FULL))
COMMON_C_FULL := $(wildcard $(COMMON_C_FULL))
COMMON_S_FULL := $(wildcard $(COMMON_S_FULL))

ALL_C_FULL := $(KYBER_C_FULL) $(COMMON_C_FULL)
ALL_S_FULL := $(KYBER_S_FULL) $(COMMON_S_FULL)

VPATH += $(sort $(dir $(ALL_C_FULL) $(ALL_S_FULL)))

SRC += $(notdir $(ALL_C_FULL))
ASRC += $(notdir $(ALL_S_FULL))

CFLAGS += -DPQM4_EXP_XAGAWA_FAILURE_HANDLING=1
CFLAGS += -Wno-unused-function
CFLAGS += -Wno-unused-variable
CFLAGS += -Wno-sign-compare
CFLAGS += -Wno-implicit-function-declaration
CFLAGS += $(EXTRA_CFLAGS)

.PHONY: print-kyber-files
print-kyber-files:
	@echo "REPO_ROOT        = $(REPO_ROOT)"
	@echo "FIRMWAREPATH     = $(FIRMWAREPATH)"
	@echo "PQM4_ROOT        = $(PQM4_ROOT)"
	@echo "KYBER_DIR        = $(KYBER_DIR)"
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
