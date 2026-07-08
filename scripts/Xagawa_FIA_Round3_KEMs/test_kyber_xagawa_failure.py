#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, List, Tuple
import chipwhisperer as cw

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SimpleSerial driver for Xagawa Kyber failure-handling fault")
    p.add_argument("--hex", required=True)
    p.add_argument("--no-program", action="store_true")
    p.add_argument("--label", default="xagawa-kyber-failure-handling")
    p.add_argument("--baud", type=int, default=230400)
    p.add_argument("--trials", type=int, default=1)
    p.add_argument("--timeout", type=float, default=2.0)
    p.add_argument("--verbose-packets", action="store_true")
    p.add_argument("--fault-enable", type=int, choices=[0, 1], default=0)
    p.add_argument("--corrupt-offset", type=int, default=0)
    p.add_argument("--corrupt-mask", type=lambda x: int(x, 0), default=1)
    p.add_argument("--expect-fail", type=int, choices=[0, 1])
    p.add_argument("--expected-fault-skips", type=int)
    p.add_argument("--expect-defense-error", type=int, choices=[0, 1])
    p.add_argument("--read-hpc-hw", action="store_true")
    p.add_argument("--ping-only", action="store_true")
    return p.parse_args()

def configure_scope(scope, args):
    scope.default_setup()
    scope.io.hs2 = "clkgen"
    scope.clock.clkgen_freq = 7_384_615
    scope.adc.timeout = 0.25

def reset_target(scope):
    import time
    scope.io.nrst = "low"; time.sleep(0.05)
    scope.io.nrst = "high"; time.sleep(0.05)

def send_cmd_read(target, cmd, response_cmd, response_len, timeout, payload=b"", verbose=False) -> bytes:
    target.simpleserial_write(cmd, bytearray(payload))
    resp = target.simpleserial_read_witherrors(response_cmd, response_len, glitch_timeout=timeout)
    if verbose:
        print(f"[debug] {cmd}->{response_cmd}: {resp}")
    if not resp.get("valid", False):
        raise RuntimeError(f"invalid response for {cmd}->{response_cmd}: {resp}")
    data = bytes(resp.get("payload", b""))
    if len(data) != response_len:
        raise RuntimeError(f"unexpected response length for {cmd}->{response_cmd}: got {len(data)}, expected {response_len}")
    return data

def configure_fault(target, args) -> Dict[str, int]:
    payload = bytes([args.fault_enable & 1, args.corrupt_offset & 0xff, args.corrupt_mask & 0xff, 0])
    r = send_cmd_read(target, "F", "F", 8, args.timeout, payload=payload, verbose=args.verbose_packets)
    d = {"ret": r[0], "fault_enable": r[1], "corrupt_offset": r[2], "corrupt_mask": r[3],
         "ct_len_low": r[4], "ct_len_high": r[5], "reserved0": r[6], "reserved1": r[7]}
    if d["ret"] != 0:
        raise RuntimeError(f"fault config failed: {d}")
    return d

def read_status(target, timeout, verbose) -> Dict[str, int]:
    r = send_cmd_read(target, "H", "H", 16, timeout, verbose=verbose)
    return {"keypair_ret": r[0], "enc_ret": r[1], "dec_ret": r[2], "fail": r[3],
            "fault_skips": int.from_bytes(r[4:8], "little"), "fault_enable": r[8],
            "corrupt_offset": r[9], "corrupt_mask": r[10], "ss_dec_eq_enc": r[11],
            "defense_error": r[12], "cmov_entries": r[13], "cmov_exits": r[14],
            "reserved": r[15], "raw": r.hex()}

def read_hpc(target, timeout, verbose) -> Dict[str, int]:
    r = send_cmd_read(target, "Y", "Y", 32, timeout, verbose=verbose)
    w = [int.from_bytes(r[i:i+4], "little") for i in range(0, 32, 4)]
    packed = w[3]
    return {"available": w[0], "anomaly": w[1], "cmov_region_cycles": w[2],
            "dwt_cpi": packed & 0xff, "dwt_exc": (packed >> 8) & 0xff,
            "dwt_lsu": (packed >> 16) & 0xff, "dwt_fold": (packed >> 24) & 0xff,
            "target_cmov_cycles": w[4], "cmov_cycles_min": w[5],
            "cmov_cycles_max": w[6], "cmov_cycles_sum": w[7]}

def print_kv(title, data):
    print(title)
    for k, v in data.items():
        print(f"  {k:24s}: {v}")

def run_trial(target, args, trial):
    print(f"\n===== Trial {trial} =====")
    print("[test] configure Xagawa failure-handling fault mode")
    print_kv("[fault-config]", configure_fault(target, args))

    print("[test] ping")
    if send_cmd_read(target, "P", "P", 1, args.timeout, verbose=args.verbose_packets)[0] != 0x42:
        raise RuntimeError("ping failed")
    if args.ping_only:
        return

    print("[test] keypair")
    if send_cmd_read(target, "K", "K", 1, args.timeout, verbose=args.verbose_packets)[0] != 0:
        raise RuntimeError("keypair failed")

    print("[test] encapsulate and corrupt ciphertext")
    if send_cmd_read(target, "E", "E", 1, args.timeout, verbose=args.verbose_packets)[0] != 0:
        raise RuntimeError("encapsulation failed")

    print("[test] decapsulate corrupted ciphertext")
    if send_cmd_read(target, "D", "D", 1, args.timeout, verbose=args.verbose_packets)[0] != 0:
        raise RuntimeError("decapsulation command failed")

    st = read_status(target, args.timeout, args.verbose_packets)
    print_kv("[result]", st)

    if args.read_hpc_hw:
        print_kv("[hpc-hw]", read_hpc(target, args.timeout, args.verbose_packets))

    if args.expect_fail is not None:
        fail_bit = 1 if st["fail"] != 0 else 0
        if fail_bit != args.expect_fail:
            raise RuntimeError(f"Unexpected fail flag: expected {args.expect_fail}, got {st['fail']}")
    if args.expected_fault_skips is not None and st["fault_skips"] != args.expected_fault_skips:
        raise RuntimeError(f"Unexpected fault_skips: expected {args.expected_fault_skips}, got {st['fault_skips']}")
    if args.expect_defense_error is not None:
        has_error = 1 if st["defense_error"] != 0 else 0
        if has_error != args.expect_defense_error:
            raise RuntimeError(f"Unexpected defense_error: expected {args.expect_defense_error}, got {st['defense_error']}")

def main():
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
    successes = 0
    failures: List[Tuple[int, str]] = []
    try:
        configure_scope(scope, args)
        if not args.no_program:
            print("[info] programming target...")
            cw.program_target(scope, cw.programmers.STM32FProgrammer, str(hex_path))
            print("[ok] programmed")
        target = cw.target(scope, cw.targets.SimpleSerial2, baud=args.baud)
        target.flush()
        reset_target(scope)
        raw = target.read(num_char=300, timeout=1000)
        print("[debug] raw UART after reset:")
        print(repr(raw))
        for trial in range(1, args.trials + 1):
            try:
                run_trial(target, args, trial)
                successes += 1
                print(f"[PASS] trial {trial}")
            except Exception as exc:
                failures.append((trial, str(exc)))
                print(f"[FAIL] trial {trial}: {exc}")
                reset_target(scope)
                target.flush()
        print("\n===== Summary =====")
        print(f"Label    : {args.label}")
        print(f"Trials   : {args.trials}")
        print(f"Successes: {successes}")
        print(f"Failures : {len(failures)}")
        if failures:
            for t, why in failures:
                print(f"  Trial {t}: {why}")
            raise SystemExit(1)
        print("\nSUCCESS: all requested trials passed.")
    finally:
        if target is not None:
            try: target.dis()
            except Exception: pass
        try: scope.dis()
        except Exception: pass

if __name__ == "__main__":
    main()
