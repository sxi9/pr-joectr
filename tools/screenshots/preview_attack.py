"""Builds the canonical attack in a throwaway store and prints what the guard concluded.

Used only for screenshots taken before the scenario runner existed; it scripts the
session by hand with the test helper instead of going through the analyzers.
"""
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests"))
os.environ.setdefault("TAINTTRAIL_KEY", "screenshot-key")

from sim import attack_session  # noqa: E402
from tainttrail import report  # noqa: E402
from tainttrail.config import Config  # noqa: E402
from tainttrail.store import Store  # noqa: E402

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp) / "project"
    root.mkdir()
    cfg = Config(root=root, home=root / ".tainttrail")
    with Store(cfg.db_path) as store:
        attack_session(store, cfg, ts=int(time.time() * 1000))
        color = report.use_color()
        what = sys.argv[1] if len(sys.argv) > 1 else "finding"
        if what == "timeline":
            print(report.render_timeline(report.timeline(store, "s1"), color=color))
        else:
            print(report.render_finding(report.get_finding(store, "last"), color=color))
