# SPDX-FileCopyrightText: 2026 CCD Enterprise & Development LLC
# SPDX-License-Identifier: Apache-2.0
"""Read-only machine inventory.

Collects basic facts using only the Python standard library. It never writes,
never opens network connections and never runs other programs (tests enforce
this). The host name is replaced by a short hash by default.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import sys
import time

from . import __version__

SCHEMA = "syrebrum.inventory/1"


def _os_facts() -> tuple[str, str, str, str]:
    """(system, release, machine, node) without running other programs.

    platform.uname() can start a subprocess on some systems, so it isn't used.
    """
    if hasattr(os, "uname"):
        u = os.uname()
        return u.sysname, u.release, u.machine, u.nodename
    if sys.platform == "win32":
        v = sys.getwindowsversion()
        return ("Windows", f"{v.major}.{v.minor}.{v.build}",
                os.environ.get("PROCESSOR_ARCHITECTURE", "unknown"), os.environ.get("COMPUTERNAME", ""))
    return sys.platform, "unknown", "unknown", ""


def collect(include_hostname: bool = False) -> dict:
    if type(include_hostname) is not bool:
        raise TypeError("include_hostname must be a bool")
    system, release, machine, node = _os_facts()
    disks = []
    for path in _mount_points():
        try:
            u = shutil.disk_usage(path)
        except OSError:
            continue
        disks.append({"path": path, "total_bytes": u.total, "free_bytes": u.free})
    report = {
        "schema": SCHEMA,
        "collected_at": round(time.time(), 3),
        "collector": f"syrebrum-core {__version__}",
        # A short hash is a pseudonym, not anonymity: anyone who can guess the name can confirm it.
        "host": node if include_hostname else "sha256:" + hashlib.sha256(node.encode()).hexdigest()[:16],
        "os": {"system": system, "release": release, "machine": machine},
        "python": ".".join(str(n) for n in sys.version_info[:3]),
        "cpu_count": os.cpu_count(),
        "disks": disks,
    }
    report["findings"] = findings(report)
    return report


def findings(report: dict) -> list[dict]:
    """Simple, explainable checks. Severity: info, low, medium, high."""
    out = []
    for d in report.get("disks", []):
        if d["total_bytes"] and d["free_bytes"] / d["total_bytes"] < 0.10:
            out.append({"id": "disk.low_free", "severity": "medium",
                        "message": f"{d['path']} has less than 10% free space"})
    return out


def _mount_points() -> list[str]:
    if os.name == "nt":
        return [f"{c}:\\" for c in "CDEFGH" if os.path.exists(f"{c}:\\")]
    return ["/"]
