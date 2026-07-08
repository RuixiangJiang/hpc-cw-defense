#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, List, Tuple

import chipwhisperer as cw

MODEL_MAP = {
    "none": 0,
    "ptr": 1,
    "value": 2,
}
MODEL_NAME = {v: k for k, v in MODEL_MAP.items()}


def parse_int(s: str) -> int:
    return int(s, 0)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SimpleSerial driver for Ravi Fiddling the Twiddle Constants")
    p.add_argument("--hex", required=True)
    p.add_argument("--no-program", action="store_true")
    p.add_argument("--label", default="ravi-fiddling-twiddle")
    p.add_argument("--baud", type=int, default=230400)
    p.add_argument("--trials", type=int, default=1)
    p.add_argument("--timeout", type=float, default=2.0)
    p.add_argument("--verbose-packets", action="store_true")
    p.add_argument("--model", choices=sorted(MODEL_MAP), default="none")
    p.add_argument("--target-j", type=parse_int, default=17)
    p.add_argument("--twiddle-index", type=parse_int, default=29)
    p.add_argument("--wrong-index", type=parse_int, default=0)
    p.add_argument("--fault-value", type=parse_int, default=0)
    p.add_argument("--expected-faults", type=int)
    p.add_argument("--read-target", action="store_true")
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
    scope.io.nrst = "low"
    time.sleep(0.05)
    scope.io.nrst = "high"
    time.sleep(0.05)


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


def configure_fault(target, args) -> Dict[str, int]:
    payload = bytearray(16)
    payload[0] = MODEL_MAP[args.model]
    payload[1:3] = u16(args.target_j)
    payload[3:5] = u16(args.twiddle_index)
    payload[5:7] = u16(args.wrong_index)
    payload[7:11] = u32(args.fault_value)

    r = send_cmd_read(target, "F", "F", 24, args.timeout, payload=bytes(payload), verbose=args.verbose_packets)
    d = {
        "ret": r[0],
        "model": r[1],
        "model_name": MODEL_NAME.get(r[1], f"unknown-{r[1]}"),
        "target_j": int.from_bytes(r[2:4], "little"),
        "twiddle_index": int.from_bytes(r[4:6], "little"),
        "wrong_index": int.from_bytes(r[6:8], "little"),
        "fault_value": int.from_bytes(r[8:12], "little", signed=False),
        "layer_len": int.from_bytes(r[12:16], "little"),
        "ncoeffs": int.from_bytes(r[16:20], "little"),
        "q": int.from_bytes(r[20:24], "little"),
        "raw": r.hex(),
    }
    if d["ret"] != 0:
        raise RuntimeError(f"fault config failed: {d}")
    return d


def read_status(target, timeout, verbose) -> Dict[str, int]:
    r = send_cmd_read(target, "H", "H", 32, timeout, verbose=verbose)
    return {
        "model": r[0],
        "model_name": MODEL_NAME.get(r[0], f"unknown-{r[0]}"),
        "target_j": int.from_bytes(r[1:3], "little"),
        "semantic_valid": r[3],
        "faults_applied": int.from_bytes(r[4:8], "little"),
        "expected_twiddle": int.from_bytes(r[8:12], "little", signed=True),
        "used_twiddle": int.from_bytes(r[12:16], "little", signed=True),
        "output_digest": int.from_bytes(r[16:20], "little"),
        "baseline_digest": int.from_bytes(r[20:24], "little"),
        "output_diff": int.from_bytes(r[24:28], "little"),
        "defense_error": r[28],
        "hpc_anomaly_byte": r[29],
        "entries": r[30],
        "exits": r[31],
        "raw": r.hex(),
    }


def read_target_status(target, timeout, verbose) -> Dict[str, int]:
    r = send_cmd_read(target, "T", "T", 32, timeout, verbose=verbose)
    return {
        "target_before_a": int.from_bytes(r[0:4], "little", signed=True),
        "target_before_b": int.from_bytes(r[4:8], "little", signed=True),
        "target_after_a": int.from_bytes(r[8:12], "little", signed=True),
        "target_after_b": int.from_bytes(r[12:16], "little", signed=True),
        "twiddle_index": int.from_bytes(r[16:20], "little"),
        "wrong_index": int.from_bytes(r[20:24], "little"),
        "fault_value": int.from_bytes(r[24:28], "little", signed=True),
        "layer_len": int.from_bytes(r[28:32], "little"),
    }


def read_hpc(target, timeout, verbose) -> Dict[str, int]:
    r = send_cmd_read(target, "Y", "Y", 32, timeout, verbose=verbose)
    w = [int.from_bytes(r[i:i + 4], "little") for i in range(0, 32, 4)]
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
        print(f"  {k:24s}: {v}")


def run_trial(target, args, trial):
    print(f"\n===== Trial {trial} =====")

    print("[test] configure twiddle fault model")
    print_kv("[fault-config]", configure_fault(target, args))

    print("[test] ping")
    if send_cmd_read(target, "P", "P", 1, args.timeout, verbose=args.verbose_packets)[0] != 0x42:
        raise RuntimeError("ping failed")
    if args.ping_only:
        return

    print("[test] init")
    if send_cmd_read(target, "K", "K", 1, args.timeout, verbose=args.verbose_packets)[0] != 0:
        raise RuntimeError("init failed")

    print("[test] run NTT layer")
    if send_cmd_read(target, "S", "S", 1, args.timeout, verbose=args.verbose_packets)[0] != 0:
        raise RuntimeError("run command returned nonzero")

    st = read_status(target, args.timeout, args.verbose_packets)
    print_kv("[result]", st)

    if args.read_target:
        print_kv("[target]", read_target_status(target, args.timeout, args.verbose_packets))

    if args.read_hpc_hw:
        print_kv("[hpc-hw]", read_hpc(target, args.timeout, args.verbose_packets))

    if args.expected_faults is not None and st["faults_applied"] != args.expected_faults:
        raise RuntimeError(f"Unexpected faults_applied: expected {args.expected_faults}, got {st['faults_applied']}")

    if st["semantic_valid"] != 1:
        raise RuntimeError("semantic_valid is not set")

    if args.model == "none" and st["output_diff"] != 0:
        raise RuntimeError(f"baseline output differs from reference: {st['output_diff']}")

    if args.model != "none" and st["output_diff"] == 0:
        raise RuntimeError("attack output did not differ from reference")


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
