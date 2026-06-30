#!/usr/bin/env bash
# Experiment-local environment:
# Fault Attacks on CCA-secure Lattice KEMs

export EXP_NAME="Fault_Attacks_on_CCA-secure_Lattice_KEMs"
export EXP_DIR="$REPO_ROOT/scripts/$EXP_NAME"

export FW_APP_DIR="$REPO_ROOT/firmware/cw-kyber51290s-decoder-skip"
export FW_TARGET_NAME="cw-kyber51290s-decoder-skip"

export KYBER_DIR="$PQM4_ROOT/crypto_kem/kyber512-90s/m4fspeed"

export PQM4_COMMON_DIR="$PQM4_ROOT/common"
export MUPQ_ROOT="$PQM4_ROOT/mupq"
export MUPQ_COMMON_DIR="$MUPQ_ROOT/common"

export PROFILE_BASELINE="$REPO_ROOT/profiles/baseline.yaml"
export PROFILE_ATTACK="$REPO_ROOT/profiles/attack_decoder_skip_qhalf.yaml"

if [ ! -d "$FW_APP_DIR" ]; then
    echo "[error] FW_APP_DIR does not exist: $FW_APP_DIR" >&2
    exit 1
fi

if [ ! -d "$KYBER_DIR" ]; then
    echo "[error] KYBER_DIR does not exist: $KYBER_DIR" >&2
    exit 1
fi

if [ ! -d "$PQM4_COMMON_DIR" ]; then
    echo "[error] PQM4_COMMON_DIR does not exist: $PQM4_COMMON_DIR" >&2
    exit 1
fi

if [ ! -d "$MUPQ_COMMON_DIR" ]; then
    echo "[error] MUPQ_COMMON_DIR does not exist: $MUPQ_COMMON_DIR" >&2
    exit 1
fi
