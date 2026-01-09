"""
Pytest configuration and shared fixtures.

SPDX-License-Identifier: AGPL-3.0-or-later
"""

import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
