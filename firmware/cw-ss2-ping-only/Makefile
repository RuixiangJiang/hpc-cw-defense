TARGET = cw-ss2-ping-only

PLATFORM ?= CWLITEARM
SS_VER ?= SS_VER_2_1
CRYPTO_TARGET = NONE
OPT ?= 3

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
THIS_MAKEFILE_DIR := $(dir $(abspath $(THIS_MAKEFILE)))
REPO_ROOT := $(abspath $(THIS_MAKEFILE_DIR)/../..)

include $(REPO_ROOT)/repo.mk

SRC = main.c

include $(FIRMWAREPATH)/simpleserial/Makefile.simpleserial
include $(FIRMWAREPATH)/Makefile.inc
