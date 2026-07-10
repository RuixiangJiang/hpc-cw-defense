#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, List, Tuple
import chipwhisperer as cw

MODEL_MAP = {"none": 0, "zero": 1, "stale": 2}
MODEL_NAME = {v: k for k, v in MODEL_MAP.items()}

def parse_int(s: str) -> int:
    return int(s, 0)

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SimpleSerial driver for Du polyz_unpack skipped-load simulation")
    p.add_argument("--hex", required=True)
    p.add_argument("--no-program", action="store_true")
    p.add_argument("--label", default="du-polyz")
    p.add_argument("--baud", type=int, default=230400)
    p.add_argument("--trials", type=int, default=1)
    p.add_argument("--timeout", type=float, default=2.0)
    p.add_argument("--verbose-packets", action="store_true")
    p.add_argument("--model", choices=sorted(MODEL_MAP), default="none")
    p.add_argument("--target-coeff", type=parse_int, default=17)
    p.add_argument("--target-load", type=parse_int, default=1)
    p.add_argument("--stale-byte", type=parse_int, default=0x5a)
    p.add_argument("--message-tweak", type=parse_int, default=0)
    p.add_argument("--expected-faults", type=int)
    p.add_argument("--read-detail", action="store_true")
    p.add_argument("--read-digest", action="store_true")
    p.add_argument("--read-hpc-hw", action="store_true")
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

def u16(x: int) -> bytes:
    return (x & 0xffff).to_bytes(2, "little")

def u32(x: int) -> bytes:
    return (x & 0xffffffff).to_bytes(4, "little")

def s32_from_u32(x: int) -> int:
    return x - 0x100000000 if x & 0x80000000 else x

def configure_fault(target, args) -> Dict[str, int]:
    payload = bytearray(16)
    payload[0] = MODEL_MAP[args.model]
    payload[1:3] = u16(args.target_coeff)
    payload[3] = args.target_load & 0xff
    payload[4] = args.stale_byte & 0xff
    payload[5:9] = u32(args.message_tweak)
    r = send_cmd_read(target, "F", "F", 24, args.timeout, payload=bytes(payload), verbose=args.verbose_packets)
    d = {
        "ret": r[0],
        "model": r[1],
        "model_name": MODEL_NAME.get(r[1], f"unknown-{r[1]}"),
        "target_coeff": int.from_bytes(r[4:8], "little"),
        "target_load": int.from_bytes(r[8:12], "little"),
        "stale_byte": int.from_bytes(r[12:16], "little"),
        "message_tweak": int.from_bytes(r[16:20], "little"),
        "packed_digest": int.from_bytes(r[20:24], "little"),
        "raw": r.hex(),
    }
    if d["ret"] != 0:
        raise RuntimeError(f"fault config failed: {d}")
    return d

def read_status(target, timeout, verbose):
    r = send_cmd_read(target, "H", "H", 32, timeout, verbose=verbose)
    expected_coeff_u32 = int.from_bytes(r[12:16], "little")
    used_coeff_u32 = int.from_bytes(r[16:20], "little")
    return {
        "model": r[0],
        "model_name": MODEL_NAME.get(r[0], f"unknown-{r[0]}"),
        "semantic_valid": r[1],
        "output_matches_ref": r[2],
        "target_load": r[3],
        "faults_applied": int.from_bytes(r[4:8], "little"),
        "target_coeff": int.from_bytes(r[8:12], "little"),
        "expected_coeff_u32": expected_coeff_u32,
        "expected_coeff_s32": s32_from_u32(expected_coeff_u32),
        "used_coeff_u32": used_coeff_u32,
        "used_coeff_s32": s32_from_u32(used_coeff_u32),
        "expected_load_value": int.from_bytes(r[20:24], "little"),
        "used_load_value": int.from_bytes(r[24:28], "little"),
        "defense_error": r[28],
        "hpc_anomaly_byte": r[29],
        "entries": r[30],
        "exits": r[31],
        "raw": r.hex(),
    }

def read_digest(target, timeout, verbose):
    r = send_cmd_read(target, "D", "D", 16, timeout, verbose=verbose)
    return {
        "output_digest": int.from_bytes(r[0:4], "little"),
        "reference_digest": int.from_bytes(r[4:8], "little"),
        "output_diff": int.from_bytes(r[8:12], "little"),
        "message_tweak": int.from_bytes(r[12:16], "little"),
    }

def read_detail(target, timeout, verbose):
    r = send_cmd_read(target, "R", "R", 16, timeout, verbose=verbose)
    return {
        "target_group": int.from_bytes(r[0:4], "little"),
        "coeff_in_group": int.from_bytes(r[4:8], "little"),
        "expected_partial": int.from_bytes(r[8:12], "little"),
        "used_partial": int.from_bytes(r[12:16], "little"),
    }

def read_hpc(target, timeout, verbose):
    r = send_cmd_read(target, "Y", "Y", 32, timeout, verbose=verbose)
    w = [int.from_bytes(r[i:i+4], "little") for i in range(0, 32, 4)]
    packed = w[3]
    return {
        "available": w[0],
        "anomaly": w[1],
        "region_cycles": w[2],
        "dwt_cpi": packed & 0xff,
        "dwt_exc": (packed >> 8) & 0xff,
        "dwt_lsu": (packed >> 16) & 0xff,
        "dwt_fold": (packed >> 24) & 0xff,
        "target_cycles": w[4],
        "cycles_min": w[5],
        "cycles_max": w[6],
        "cycles_sum": w[7],
    }

def print_kv(title, data):
    print(title)
    for k, v in data.items():
        print(f"  {k:28s}: {v}")

def run_trial(target, args, trial):
    print(f"\n===== Trial {trial} =====")
    cfg = configure_fault(target, args)
    print_kv("[fault-config]", cfg)
    if send_cmd_read(target, "P", "P", 1, args.timeout, verbose=args.verbose_packets)[0] != 0x42:
        raise RuntimeError("ping failed")
    if send_cmd_read(target, "K", "K", 1, args.timeout, verbose=args.verbose_packets)[0] != 0:
        raise RuntimeError("init failed")
    if send_cmd_read(target, "S", "S", 1, args.timeout, verbose=args.verbose_packets)[0] != 0:
        raise RuntimeError("run failed")
    st = read_status(target, args.timeout, args.verbose_packets)
    print_kv("[result]", st)
    detail = None
    if args.read_detail:
        detail = read_detail(target, args.timeout, args.verbose_packets)
        print_kv("[detail]", detail)
    dg = None
    if args.read_digest:
        dg = read_digest(target, args.timeout, args.verbose_packets)
        print_kv("[digest]", dg)
    if args.read_hpc_hw:
        print_kv("[hpc-hw]", read_hpc(target, args.timeout, args.verbose_packets))

    if args.expected_faults is not None and st["faults_applied"] != args.expected_faults:
        raise RuntimeError(f"Unexpected faults_applied: expected {args.expected_faults}, got {st['faults_applied']}")
    if st["semantic_valid"] != 1:
        raise RuntimeError("semantic_valid is not set")

    if args.model == "none":
        if st["output_matches_ref"] != 1:
            raise RuntimeError("baseline output does not match reference")
        if st["expected_coeff_u32"] != st["used_coeff_u32"]:
            raise RuntimeError("baseline target coefficient changed")
        if dg is not None and dg["output_diff"] != 0:
            raise RuntimeError("baseline digest mismatch")
    else:
        if st["faults_applied"] != 1:
            raise RuntimeError("attack did not apply exactly one local load fault")
        if args.model == "zero" and st["used_load_value"] != 0:
            raise RuntimeError("zero model did not use zero load result")
        if args.model == "stale" and st["used_load_value"] != (args.stale_byte & 0xff):
            raise RuntimeError("stale model did not use stale load result")
        if st["expected_load_value"] == st["used_load_value"]:
            print("[warn] replacement equals natural load byte; semantic output may be unchanged")
        if dg is not None and dg["output_diff"] == 0:
            print("[warn] output matches reference for this target/load/replacement; choose another target")

def main():
    args = parse_args()
    hex_path = Path(args.hex).expanduser().resolve()
    if not args.no_program and not hex_path.exists():
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
                reset_target(scope); target.flush()
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
