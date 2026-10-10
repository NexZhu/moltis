#!/usr/bin/env python3
import runpy
import sys
from pathlib import Path
sys.argv.append("--fetch")
runpy.run_path(str(Path(__file__).with_name("image-proof.py")), run_name="__main__")
