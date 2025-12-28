#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    # Allow running without installation by adding `net-traffic-sim/src` to `sys.path`.
    repo_src = Path(__file__).resolve().parent / "src"
    sys.path.insert(0, str(repo_src))

    from net_traffic_sim.cli import main as package_main

    return package_main()


if __name__ == "__main__":
    raise SystemExit(main())
