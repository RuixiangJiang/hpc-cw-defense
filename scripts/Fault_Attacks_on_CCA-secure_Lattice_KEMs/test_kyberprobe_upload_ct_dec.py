#!/usr/bin/env python3

import argparse
import time
from pathlib import Path
from typing import Optional, Tuple, List

import chipwhisperer as cw


SS_LEN = 32
CT_LEN = 768
CT_CHUNK = 128

DEFAULT_CLKGEN_FREQ = 7_384_615.384615385
DEFAULT_ADC_SRC = "clkgen_x4"
DEFAULT_HS2 = "clkgen"
DEFAULT_BAUD = 230400


def reset_target(scope) -> None:
    scope.io.nrst = "low"
    time.sleep(0.05)
    scope.io.nrst = "high_z"
    time.sleep(0.8)


def configure_scope(scope, args) -> None:
    scope.default_setup()

    scope.gain.mode = "high"
    scope.gain.gain = 30

    scope.adc.samples = 5000
    scope.adc.basic_mode = "rising_edge"

    scope.clock.clkgen_freq = args.clkgen_freq
    scope.clock.adc_src = args.adc_src

    scope.io.hs2 = args.hs2
    scope.io.tio1 = "serial_rx"
    scope.io.tio2 = "serial_tx"
    scope.io.nrst = "high_z"


def ss2_read(target, response_cmd: str, response_len: int, timeout: float):
    try:
        return target.simpleserial_read_witherrors(
            response_cmd,
            response_len,
            timeout=timeout,
        )
    except TypeError:
        return target.simpleserial_read_witherrors(
            response_cmd,
            response_len,
            glitch_timeout=timeout,
        )


def send_cmd_read(
    target,
    cmd: str,
    response_cmd: str,
    response_len: int,
    timeout: float = 10.0,
    payload=None,
    verbose: bool = True,
) -> bytes:
    """
    Send one SimpleSerial2 command and read one response packet.

    This follows the previously verified script style:
      target.simpleserial_write(cmd, payload)
      target.simpleserial_read_witherrors(response_cmd, response_len, glitch_timeout=...)
    """
    target.flush()

    if payload is None:
        payload = bytearray([])
    else:
        payload = bytearray(payload)

    target.simpleserial_write(cmd, payload)

    result = target.simpleserial_read_witherrors(
        response_cmd,
        response_len,
        glitch_timeout=timeout,
    )

    if verbose:
        print(f"[debug] {cmd} -> {response_cmd}: {result}")

    if not result.get("valid", False):
        raise RuntimeError(f"Invalid response for command {cmd}: {result}")

    response_payload = bytes(result["payload"])

    if len(response_payload) != response_len:
        raise RuntimeError(
            f"Unexpected payload length for command {cmd}: "
            f"expected {response_len}, got {len(response_payload)}"
        )

    return response_payload


def read_ct(target, timeout: float = 10.0, verbose: bool = True) -> bytes:
    """Read ciphertext from target in 128-byte chunks."""
    ct = bytearray()

    for offset in range(0, CT_LEN, CT_CHUNK):
        request = offset.to_bytes(2, "little") + bytes([CT_CHUNK])

        target.flush()
        target.simpleserial_write("T", bytearray(request))

        result = target.simpleserial_read_witherrors(
            "T",
            CT_CHUNK,
            glitch_timeout=timeout,
        )

        if verbose:
            print(f"[debug] T offset {offset}: {result}")

        if not result.get("valid", False):
            raise RuntimeError(f"Invalid T response at offset {offset}: {result}")

        payload = bytes(result["payload"])

        if len(payload) != CT_CHUNK:
            raise RuntimeError(
                f"Unexpected T length at offset {offset}: "
                f"expected {CT_CHUNK}, got {len(payload)}"
            )

        ct += payload

    return bytes(ct)


def upload_ct(target, ct: bytes, timeout: float = 10.0, verbose: bool = True) -> None:
    """Upload ciphertext to target in 128-byte chunks."""
    if len(ct) != CT_LEN:
        raise ValueError(f"Unexpected ciphertext length: {len(ct)}")

    for offset in range(0, CT_LEN, CT_CHUNK):
        chunk = ct[offset:offset + CT_CHUNK]
        request = offset.to_bytes(2, "little") + chunk

        target.flush()
        target.simpleserial_write("C", bytearray(request))

        result = target.simpleserial_read_witherrors(
            "C",
            1,
            glitch_timeout=timeout,
        )

        if verbose:
            print(f"[debug] C offset {offset}: {result}")

        if not result.get("valid", False):
            raise RuntimeError(f"Invalid C response at offset {offset}: {result}")

        ret = bytes(result["payload"])[0]

        if ret != 0:
            raise RuntimeError(f"C command failed at offset {offset}, ret={ret}")


def read_status(target, timeout: float, verbose: bool = True) -> Tuple[bytes, dict]:
    payload = send_cmd_read(
        target,
        cmd="H",
        response_cmd="H",
        response_len=16,
        timeout=timeout,
        payload=b"",
        verbose=verbose,
    )

    fault_skips = (
        payload[4]
        | (payload[5] << 8)
        | (payload[6] << 16)
        | (payload[7] << 24)
    )

    status = {
        "keygen_ret": payload[0],
        "enc_ret": payload[1],
        "dec_ret": payload[2],
        "target_ss_match": payload[3],
        "fault_skips": fault_skips,
        "crypto_bytes": payload[8],
        "ct_len": payload[9] | (payload[10] << 8),
        "pk_len": payload[11] | (payload[12] << 8),
        "decode_defense_error": payload[13],
        "decode_dup_mismatches": payload[14],
        "decode_full_mismatches": payload[15],
    }

    return payload, status

def read_hpc_hw(target, timeout: float, verbose: bool = True) -> dict:
    payload = send_cmd_read(
        target,
        cmd="Y",
        response_cmd="Y",
        response_len=32,
        timeout=timeout,
        payload=b"",
        verbose=verbose,
    )

    words = [
        int.from_bytes(payload[i:i + 4], "little")
        for i in range(0, 32, 4)
    ]

    packed_events = words[3]

    info = {
        "hpc_hw_available": words[0],
        "hpc_hw_anomaly": words[1],
        "decode_cycles": words[2],
        "decode_cpi": packed_events & 0xff,
        "decode_exc": (packed_events >> 8) & 0xff,
        "decode_lsu": (packed_events >> 16) & 0xff,
        "decode_fold": (packed_events >> 24) & 0xff,
        "target_coeff_cycles": words[4],
        "coeff_cycles_min": words[5],
        "coeff_cycles_max": words[6],
        "coeff_cycles_sum": words[7],
    }

    return info


def run_one_trial(target, args, trial_id: int) -> bool:
    print(f"\n===== Trial {trial_id} =====")

    print("[test] ping")
    p_payload = send_cmd_read(
        target,
        "P",
        "P",
        1,
        timeout=args.timeout,
        verbose=args.verbose_packets,
    )

    if p_payload != b"\x42":
        raise RuntimeError(f"Unexpected ping payload: {p_payload!r}")

    if args.ping_only:
        print("[PASS] ping-only test passed")
        return True

    print("[test] keypair")
    k_payload = send_cmd_read(
        target,
        "K",
        "K",
        1,
        timeout=args.long_timeout,
        verbose=args.verbose_packets,
    )
    k_ret = k_payload[0]

    if k_ret != 0:
        raise RuntimeError(f"Keypair failed with return code {k_ret}")

    print("[test] encaps")
    e_payload = send_cmd_read(
        target,
        "E",
        "E",
        1 + SS_LEN,
        timeout=args.long_timeout,
        verbose=args.verbose_packets,
    )
    e_ret = e_payload[0]
    ss_enc = e_payload[1:]

    if e_ret != 0:
        raise RuntimeError(f"Encapsulation failed with return code {e_ret}")

    if len(ss_enc) != SS_LEN:
        raise RuntimeError(f"Unexpected ss_enc length: {len(ss_enc)}")

    print("[test] read target-generated ciphertext")
    ct = read_ct(target, timeout=args.timeout, verbose=args.verbose_packets)

    if len(ct) != CT_LEN:
        raise RuntimeError(f"Unexpected ciphertext length: {len(ct)}")

    print("[test] upload ciphertext back to target")
    upload_ct(target, ct, timeout=args.timeout, verbose=args.verbose_packets)

    print("[test] decaps")
    d_payload = send_cmd_read(
        target,
        "D",
        "S",
        1 + SS_LEN,
        timeout=args.long_timeout,
        verbose=args.verbose_packets,
    )
    d_ret = d_payload[0]
    ss_dec = d_payload[1:]

    if d_ret != 0:
        if args.allow_defense_fail and d_ret == 0xFD:
            print("[ok] decapsulation rejected by DecodeMessage defense")
        else:
            raise RuntimeError(f"Decapsulation failed with return code {d_ret}")

    if len(ss_dec) != SS_LEN:
        raise RuntimeError(f"Unexpected ss_dec length: {len(ss_dec)}")

    host_ss_match = int(ss_enc == ss_dec)

    print("[test] status")
    status_raw, status = read_status(
        target,
        timeout=args.timeout,
        verbose=args.verbose_packets,
    )

    if args.expect_defense_error is not None:
        got = 1 if status["decode_defense_error"] != 0 else 0
        if got != args.expect_defense_error:
            raise RuntimeError(
                f"Unexpected decode_defense_error: expected "
                f"{args.expect_defense_error}, got {status['decode_defense_error']}"
            )
    
    hpc_hw = None

    if args.read_hpc_hw:
        print("[test] hardware DWT counters")
        hpc_hw = read_hpc_hw(
            target,
            timeout=args.timeout,
            verbose=args.verbose_packets,
        )

        print("[hpc-hw]")
        print(f"  available           : {hpc_hw['hpc_hw_available']}")
        print(f"  anomaly             : {hpc_hw['hpc_hw_anomaly']}")
        print(f"  decode_cycles       : {hpc_hw['decode_cycles']}")
        print(f"  decode_cpi          : {hpc_hw['decode_cpi']}")
        print(f"  decode_exc          : {hpc_hw['decode_exc']}")
        print(f"  decode_lsu          : {hpc_hw['decode_lsu']}")
        print(f"  decode_fold         : {hpc_hw['decode_fold']}")
        print(f"  target_coeff_cycles : {hpc_hw['target_coeff_cycles']}")
        print(f"  coeff_cycles_min    : {hpc_hw['coeff_cycles_min']}")
        print(f"  coeff_cycles_max    : {hpc_hw['coeff_cycles_max']}")
        print(f"  coeff_cycles_sum    : {hpc_hw['coeff_cycles_sum']}")

    print("[result]")
    print(f"  status_raw       : {status_raw.hex()}")
    print(f"  keygen_ret       : {status['keygen_ret']}")
    print(f"  enc_ret          : {status['enc_ret']}")
    print(f"  dec_ret          : {status['dec_ret']}")
    print(f"  target_ss_match  : {status['target_ss_match']}")
    print(f"  host_ss_match    : {host_ss_match}")
    print(f"  fault_skips      : {status['fault_skips']}")
    print(f"  ss_enc           : {ss_enc.hex()}")
    print(f"  ss_dec           : {ss_dec.hex()}")
    print(f"  decode_error     : {status['decode_defense_error']}")
    print(f"  dup_mismatches   : {status['decode_dup_mismatches']}")
    print(f"  full_mismatches  : {status['decode_full_mismatches']}")

    if args.expected_fault_skips is not None:
        if status["fault_skips"] != args.expected_fault_skips:
            raise RuntimeError(
                f"Unexpected fault_skips: expected {args.expected_fault_skips}, "
                f"got {status['fault_skips']}"
            )

    if args.expect_ss_match is not None:
        expected = int(args.expect_ss_match)

        if status["target_ss_match"] != expected:
            raise RuntimeError(
                f"Unexpected target_ss_match: expected {expected}, "
                f"got {status['target_ss_match']}"
            )

        if host_ss_match != expected:
            raise RuntimeError(
                f"Unexpected host_ss_match: expected {expected}, "
                f"got {host_ss_match}"
            )

    return True


def parse_args():
    parser = argparse.ArgumentParser(
        description="Test Kyber512-90s ChipWhisperer probe firmware."
    )

    parser.add_argument(
        "--hex",
        required=True,
        help="Firmware hex path to program.",
    )
    parser.add_argument(
        "--label",
        default="kyberprobe",
        help="Label printed in logs.",
    )
    parser.add_argument(
        "--trials",
        type=int,
        default=1,
        help="Number of K/E/T/C/D trials.",
    )
    parser.add_argument(
        "--baud",
        type=int,
        default=DEFAULT_BAUD,
        help="SimpleSerial baudrate.",
    )
    parser.add_argument(
        "--clkgen-freq",
        type=float,
        default=DEFAULT_CLKGEN_FREQ,
        help="ChipWhisperer clkgen frequency.",
    )
    parser.add_argument(
        "--adc-src",
        default=DEFAULT_ADC_SRC,
        help="ChipWhisperer ADC source.",
    )
    parser.add_argument(
        "--hs2",
        default=DEFAULT_HS2,
        help="ChipWhisperer HS2 setting.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Normal SimpleSerial response timeout.",
    )
    parser.add_argument(
        "--long-timeout",
        type=float,
        default=60.0,
        help="Timeout for keygen/encaps/decaps.",
    )
    parser.add_argument(
        "--expected-fault-skips",
        type=int,
        default=None,
        help="Expected hpc_cw_fault_skips value from status command H.",
    )
    parser.add_argument(
        "--expect-ss-match",
        type=int,
        choices=[0, 1],
        default=None,
        help="Expected shared-secret match result.",
    )
    parser.add_argument(
        "--ping-only",
        action="store_true",
        help="Only run P -> P ping.",
    )
    parser.add_argument(
        "--no-program",
        action="store_true",
        help="Do not program target; use currently flashed firmware.",
    )
    parser.add_argument(
        "--verbose-packets",
        action="store_true",
        help="Print every SimpleSerial packet response.",
    )
    parser.add_argument(
        "--allow-defense-fail",
        action="store_true",
        help="Allow D command to return 0xFD when DecodeMessage defense fires.",
    )
    parser.add_argument(
        "--expect-defense-error",
        type=int,
        choices=[0, 1],
        default=None,
        help="Expected nonzero DecodeMessage defense error flag.",
    )
    parser.add_argument(
        "--read-hpc-hw",
        action="store_true",
        help="Read hardware DWT counters via Y command after decapsulation.",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    hex_path = Path(args.hex).expanduser().resolve()

    if not hex_path.exists() and not args.no_program:
        raise FileNotFoundError(hex_path)

    print(f"[info] label: {args.label}")
    print(f"[info] hex:   {hex_path}")
    print(f"[info] baud:  {args.baud}")

    print("[info] available ChipWhisperer devices:")
    print(cw.list_devices())

    scope = cw.scope()
    target = None

    success_count = 0
    failure_count = 0
    failures: List[Tuple[int, str]] = []

    try:
        configure_scope(scope, args)

        if not args.no_program:
            print("[info] programming target...")
            cw.program_target(
                scope,
                cw.programmers.STM32FProgrammer,
                str(hex_path),
            )
            print("[ok] programmed")

        target = cw.target(scope, cw.targets.SimpleSerial2, baud=args.baud)

        target.flush()
        reset_target(scope)

        raw = target.read(num_char=300, timeout=1000)
        print("[debug] raw UART after reset:")
        print(repr(raw))

        for trial in range(1, args.trials + 1):
            try:
                run_one_trial(target, args, trial)
                success_count += 1
                print(f"[PASS] trial {trial}")
            except Exception as exc:
                failure_count += 1
                failures.append((trial, str(exc)))
                print(f"[FAIL] trial {trial}: {exc}")

                reset_target(scope)
                target.flush()

                if args.ping_only:
                    break

        print("\n===== Summary =====")
        print(f"Label    : {args.label}")
        print(f"Trials   : {args.trials}")
        print(f"Successes: {success_count}")
        print(f"Failures : {failure_count}")

        if failures:
            print("\nFailure details:")
            for trial_id, reason in failures:
                print(f"  Trial {trial_id}: {reason}")

        if failure_count != 0:
            raise SystemExit(1)

        print("\nSUCCESS: all requested trials passed.")

    finally:
        if target is not None:
            try:
                target.dis()
            except Exception:
                pass

        try:
            scope.dis()
        except Exception:
            pass


if __name__ == "__main__":
    main()