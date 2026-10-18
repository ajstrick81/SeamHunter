import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from autopsy.cli import main  # noqa: E402

main()
