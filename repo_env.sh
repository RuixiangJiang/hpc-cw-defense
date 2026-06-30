#!/usr/bin/env bash
# Global environment for hpc-cw-defense.
# Keep only project-wide settings here.

export REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

export THIRD_PARTY_DIR="$REPO_ROOT/third_party"

export CHIPWHISPERER_ROOT="$THIRD_PARTY_DIR/chipwhisperer"
export CW_FIRMWARE_DIR="$CHIPWHISPERER_ROOT/firmware/mcu"

# pqm4 is now the normalized local name for pqm4 Round3.
export PQM4_ROOT="$THIRD_PARTY_DIR/pqm4"

export DEFAULT_PLATFORM="CWLITEARM"
export DEFAULT_SS_VER="SS_VER_2_1"
export DEFAULT_CRYPTO_TARGET="NONE"
