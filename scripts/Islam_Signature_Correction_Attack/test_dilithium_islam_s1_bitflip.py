#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, List, Tuple

import chipwhisperer as cw


def parse_int(s: str) -> int:
    return int(s, 0)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SimpleSerial driver for Islam Dilithium s1 bit-flip attack")
    p.add_argument("--hex", required=True)
    p.add_argument("--no-program", action="store_true")
    p.add_argument("--label", default="islam-dilithium-s1-bitflip")
    p.add_argument("--baud", type=int, default=230400)
    p.add_argument("--trials", type=int, default=1)
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--verbose-packets", action="store_true")
    p.add_argument("--fault-enable", type=int, choices=[0, 1], default=0)
    p.add_argument("--s1-byte-offset", type=parse_int, default=0)
    p.add_argument("--bit-mask", type=parse_int, default=1)
    p.add_argument("--restore-after-sign", type=int, choices=[0, 1], default=1)
    p.add_argument("--verify-after-sign", type=int, choices=[0, 1], default=0)
    p.add_argument("--message", default="Islam Signature Correction Attack")
    p.add_argument("--expected-faults", type=int)
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


def configure_fault(target, args) -> Dict[str, int]:
    payload = bytearray(16)
    payload[0] = args.fault_enable & 1
    payload[1:3] = (args.s1_byte_offset & 0xffff).to_bytes(2, "little")
    payload[3] = args.bit_mask & 0xff
    payload[4] = args.restore_after_sign & 1
    payload[5] = args.verify_after_sign & 1

    r = send_cmd_read(target, "F", "F", 16, args.timeout, payload=bytes(payload), verbose=args.verbose_packets)
    d = {
        "ret": r[0],
        "fault_enable": r[1],
        "s1_byte_offset": int.from_bytes(r[2:4], "little"),
        "bit_mask": r[4],
        "restore_after_sign": r[5],
        "verify_after_sign": r[6],
        "s1_base_offset": int.from_bytes(r[8:12], "little"),
        "s1_bytes": int.from_bytes(r[12:14], "little"),
        "raw": r.hex(),
    }
    if d["ret"] != 0:
        raise RuntimeError(f"fault config failed: {d}")
    return d


def upload_message(target, args) -> None:
    msg = args.message.encode("utf-8")[:127]
    payload = bytearray(128)
    payload[0] = len(msg)
    payload[1:1 + len(msg)] = msg
    r = send_cmd_read(target, "M", "M", 1, args.timeout, payload=bytes(payload), verbose=args.verbose_packets)
    if r[0] != 0:
        raise RuntimeError(f"message upload failed: ret={r[0]}")


def read_status(target, timeout, verbose) -> Dict[str, int]:
    r = send_cmd_read(target, "H", "H", 32, timeout, verbose=verbose)
    return {
        "keypair_ret": r[0],
        "sign_ret": r[1],
        "verify_ret_u8": r[2],
        "semantic_valid": r[3],
        "faults_applied": int.from_bytes(r[4:8], "little"),
        "fault_enable": r[8],
        "s1_byte_offset": int.from_bytes(r[9:11], "little"),
        "bit_mask": r[11],
        "abs_sk_offset": int.from_bytes(r[12:16], "little"),
        "byte_before": r[16],
        "byte_faulted": r[17],
        "byte_after": r[18],
        "restore_ok": r[19],
        "sig_len": int.from_bytes(r[20:24], "little"),
        "sig_digest": int.from_bytes(r[24:28], "little"),
        "defense_error": r[28],
        "hpc_anomaly_byte": r[29],
        "restore_after_sign": r[30],
        "verify_after_sign": r[31],
        "raw": r.hex(),
    }


def read_hpc(target, timeout, verbose) -> Dict[str, int]:
    r = send_cmd_read(target, "Y", "Y", 32, timeout, verbose=verbose)
    w = [int.from_bytes(r[i:i + 4], "little") for i in range(0, 32, 4)]
    packed = w[3]
    return {
        "available": w[0],
        "anomaly": w[1],
        "sign_region_cycles": w[2],
        "dwt_cpi": packed & 0xff,
        "dwt_exc": (packed >> 8) & 0xff,
        "dwt_lsu": (packed >> 16) & 0xff,
        "dwt_fold": (packed >> 24) & 0xff,
        "sign_cycles": w[4],
        "reserved5": w[5],
        "reserved6": w[6],
        "reserved7": w[7],
    }


def print_kv(title, data):
    print(title)
    for k, v in data.items():
        print(f"  {k:24s}: {v}")


def run_trial(target, args, trial):
    print(f"\n===== Trial {trial} =====")

    print("[test] configure s1 bit-flip model")
    print_kv("[fault-config]", configure_fault(target, args))

    print("[test] ping")
    if send_cmd_read(target, "P", "P", 1, args.timeout, verbose=args.verbose_packets)[0] != 0x42:
        raise RuntimeError("ping failed")
    if args.ping_only:
        return

    print("[test] keypair")
    if send_cmd_read(target, "K", "K", 1, args.timeout, verbose=args.verbose_packets)[0] != 0:
        raise RuntimeError("keypair failed")

    print("[test] upload message")
    upload_message(target, args)

    print("[test] sign")
    if send_cmd_read(target, "S", "S", 1, args.timeout, verbose=args.verbose_packets)[0] != 0:
        raise RuntimeError("sign command returned nonzero")

    st = read_status(target, args.timeout, args.verbose_packets)
    print_kv("[result]", st)

    if args.read_hpc_hw:
        print_kv("[hpc-hw]", read_hpc(target, args.timeout, args.verbose_packets))

    if args.expected_faults is not None and st["faults_applied"] != args.expected_faults:
        raise RuntimeError(f"Unexpected faults_applied: expected {args.expected_faults}, got {st['faults_applied']}")

    if st["semantic_valid"] != 1:
        raise RuntimeError("semantic_valid is not set")

    if st["fault_enable"] == 1:
        expected_faulted = st["byte_before"] ^ st["bit_mask"]
        if st["byte_faulted"] != expected_faulted:
            raise RuntimeError(
                f"faulted byte mismatch: expected {expected_faulted}, got {st['byte_faulted']}"
            )
        if st["restore_after_sign"] == 1 and st["restore_ok"] != 1:
            raise RuntimeError("secret key byte was not restored")
    else:
        if st["byte_faulted"] != st["byte_before"]:
            raise RuntimeError("baseline unexpectedly changed sk byte")


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
