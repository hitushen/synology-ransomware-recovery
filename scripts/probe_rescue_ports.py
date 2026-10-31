#!/usr/bin/env python3
"""Bounded TCP probes of one specified rescue host; no login or payload."""
import argparse
import datetime
import json
from pathlib import Path
import socket


def probe(host, ports, timeout):
    results = []
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                status = "tcp-open"
        except OSError as error:
            status = "unreachable-or-closed"
            results.append({"port": port, "status": status,
                            "error_type": type(error).__name__, "errno": error.errno})
        else:
            results.append({"port": port, "status": status})
    return {"host": host, "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "results": results, "scope": "TCP connect only; no service identification or login"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="One explicitly selected IP or hostname")
    parser.add_argument("--ports", type=int, nargs="+", default=[23, 22, 5000, 5001])
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--output", help="New JSON receipt on independent storage")
    args = parser.parse_args()
    if not args.host.strip() or any(c in args.host for c in "/*, "):
        parser.error("Specify a single host, not a range or URL")
    ports = list(dict.fromkeys(args.ports))
    if len(ports) > 16 or any(p < 1 or p > 65535 for p in ports):
        parser.error("Specify 1 to 16 valid TCP ports")
    if not 0 < args.timeout <= 10:
        parser.error("Timeout must be greater than zero and at most 10 seconds")
    if args.output and Path(args.output).exists():
        parser.error("Receipt already exists; choose a new output")
    result = probe(args.host, ports, args.timeout)
    payload = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        with open(args.output, "x", encoding="utf-8") as stream:
            stream.write(payload)
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
