"""Where the Quectel download agent is: the copy in this repo (assets/), which every build bundles, else the vendor path.

A path the user saved earlier is used only while the file still exists, so moving the checkout cannot hide the built-in copy.
"""
from pathlib import Path

from common import VENDOR_DA

REPO_DA = Path(__file__).resolve().parent / "assets" / "DA_BR.bin"


def default():
    return REPO_DA if REPO_DA.is_file() else VENDOR_DA


def pick(saved=""):
    return Path(saved) if saved and Path(saved).is_file() else default()
