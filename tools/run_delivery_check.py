#!/usr/bin/env python3
"""One-command delivery gate for VmpProject."""

import argparse
import os
import sys
from pathlib import Path

from _common.env_utils import runCmd


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Run delivery gate checks sequentially: "
            "route4 regression (with patchbay) + demo smoke verify."
        )
    )
    parser.add_argument("--project-root", default=str(Path(__file__).parent.parent))
    parser.add_argument(
        "--skip-demo",
        action="store_true",
        help="Skip demo smoke verification step.",
    )
    parser.add_argument(
        "--skip-regression",
        action="store_true",
        help="Skip route4 regression step.",
    )
    args = parser.parse_args()

    root = Path(os.path.abspath(args.project_root))
    if not root.exists():
        raise RuntimeError(f"project root not found: {root}")

    checks = []
    if not args.skip_regression:
        checks.append(
            (
                "route4_regression",
                [
                    "python",
                    "tools/run_regression.py",
                    "--project-root",
                    str(root),
                    "--patch-vmengine-symbols",
                ],
            )
        )
    if not args.skip_demo:
        checks.append(
            (
                "demo_smoke",
                [
                    "python",
                    "tools/run_demo_vmp_verify.py",
                    "--project-root",
                    str(root),
                ],
            )
        )

    if not checks:
        print("No checks selected. Use without --skip-* to run delivery gate.")
        return 0

    results = []
    for name, cmd in checks:
        print(f"\n=== DELIVERY CHECK: {name} ===")
        proc = runCmd(cmd, cwd=str(root), check=False)
        ok = proc.returncode == 0
        results.append((name, ok))
        if not ok:
            print(f"[FAIL] {name}")
            break
        print(f"[PASS] {name}")

    print("\n=== DELIVERY SUMMARY ===")
    all_pass = True
    for name, ok in results:
        print(f"- {name}: {'PASS' if ok else 'FAIL'}")
        all_pass = all_pass and ok
    if all_pass and len(results) == len(checks):
        print("DELIVERY_GATE PASS")
        return 0
    print("DELIVERY_GATE FAIL")
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)
