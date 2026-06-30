# Experiment-local Makefile configuration:
# Fault Attacks on CCA-secure Lattice KEMs

EXP_NAME := Fault_Attacks_on_CCA-secure_Lattice_KEMs
EXP_DIR := $(REPO_ROOT)/scripts/$(EXP_NAME)

FW_TARGET_NAME := cw-kyber51290s-decoder-skip
FW_APP_DIR := $(REPO_ROOT)/firmware/cw-kyber51290s-decoder-skip

KYBER_NAME ?= kyber512-90s
KYBER_IMPL ?= m4fspeed

KYBER_KEM_ROOT := $(PQM4_ROOT)/crypto_kem
KYBER_DIR := $(KYBER_KEM_ROOT)/$(KYBER_NAME)/$(KYBER_IMPL)

# Extra Kyber implementation directories needed by pqm4 Round3 assembly includes,
# e.g., matacc_asm.S includes "matacc.i" from one of these locations.
KYBER_INC_DIRS := \
	$(KYBER_KEM_ROOT)/kyber512-90s/$(KYBER_IMPL) \
	$(KYBER_KEM_ROOT)/kyber512/$(KYBER_IMPL) \
	$(KYBER_KEM_ROOT)/kyber768-90s/$(KYBER_IMPL) \
	$(KYBER_KEM_ROOT)/kyber768/$(KYBER_IMPL)

# pqm4 Round3 has two relevant common locations.
PQM4_COMMON_DIR := $(PQM4_ROOT)/common
MUPQ_ROOT := $(PQM4_ROOT)/mupq
MUPQ_COMMON_DIR := $(MUPQ_ROOT)/common
