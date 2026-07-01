#!/usr/bin/env python3
import argparse
import time
from pathlib import Path
import chipwhisperer as cw


def configure_scope(scope):
    scope.default_setup()

    # Explicit CWLITEARM / STM32F3 clock setup.
    scope.clock.clkgen_freq = 7372800
    scope.clock.adc_src = "clkgen_x4"

    scope.io.hs2 = "clkgen"
    scope.io.tio1 = "serial_rx"
    scope.io.tio2 = "serial_tx"
    scope.io.nrst = "high_z"

    try:
        print("[info] clkgen_freq:", scope.clock.clkgen_freq)
        print("[info] adc_freq:   ", scope.clock.adc_freq)
        print("[info] hs2:        ", scope.io.hs2)
        print("[info] tio1:       ", scope.io.tio1)
        print("[info] tio2:       ", scope.io.tio2)
    except Exception:
        pass


def reset_target(scope):
    scope.io.nrst = "low"
    time.sleep(0.1)
    scope.io.nrst = "high_z"
    time.sleep(0.5)


def raw_read(target, seconds=1.0):
    print(f"[debug] raw read for {seconds:.1f}s")
    end = time.time() + seconds
    chunks = []

    while time.time() < end:
        try:
            x = target.read(timeout=0.1)
            if x:
                chunks.append(x)
        except Exception:
            pass

    if chunks:
        print("[debug] raw chunks:", chunks)
    else:
        print("[debug] raw chunks: <empty>")


def read_ss2(target, cmd, length, timeout=2.0):
    try:
        return target.simpleserial_read_witherrors(cmd, length, timeout=timeout)
    except TypeError:
        return target.simpleserial_read_witherrors(cmd, length, glitch_timeout=timeout)


def read_ss2(target, cmd, length, timeout=2.0):
    try:
        return target.simpleserial_read_witherrors(cmd, length, timeout=timeout)
    except TypeError:
        return target.simpleserial_read_witherrors(cmd, length, glitch_timeout=timeout)


def try_ping(target, timeout=5.0):
    target.flush()

    data = bytearray([0x00] * 16)

    print("[debug] sending x with 16 dummy bytes")

    if hasattr(target, "send_cmd"):
        print("[debug] using target.send_cmd('x', 0x00, data)")
        target.send_cmd("x", 0x00, data)
    else:
        print("[debug] using target.simpleserial_write('x', data)")
        target.simpleserial_write("x", data)

    print("[debug] read payload frame 'r'")
    resp_r = read_ss2(target, "r", 4, timeout=timeout)
    print("[debug] r response:", resp_r)

    print("[debug] read status frame 'e'")
    resp_e = read_ss2(target, "e", 1, timeout=1.0)
    print("[debug] e response:", resp_e)

    if resp_r.get("valid"):
        payload = bytes(resp_r["payload"])
        print("[ok] payload:", payload)
        return payload

    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hex", required=True)
    parser.add_argument("--baud", type=int, default=230400)
    parser.add_argument("--no-flash", action="store_true")
    args = parser.parse_args()

    hex_path = Path(args.hex).expanduser().resolve()

    scope = cw.scope()
    target = None

    try:
        configure_scope(scope)

        if not args.no_flash:
            print("[info] programming:", hex_path)
            cw.program_target(scope, cw.programmers.STM32FProgrammer, str(hex_path))
            print("[ok] programmed")
            time.sleep(0.5)

        target = cw.target(scope, cw.targets.SimpleSerial2)
        target.baud = args.baud
        print("[info] target baud:", target.baud)

        reset_target(scope)

        # If firmware reaches init_uart()+putch('B'), this should show something.
        raw_read(target, seconds=1.0)

        print("[test] SS2 ping")
        payload = try_ping(target)

        if payload == b"PONG":
            print("[PASS] SS2 ping-only firmware works")
        else:
            raise RuntimeError("SS2 ping failed")

    finally:
        if target is not None:
            target.dis()
        scope.dis()


if __name__ == "__main__":
    main()
