"""
src/core/logger.py

Shared structured logger for Project Swarm.
"""

from __future__ import annotations

import logging
import os
from dotenv import load_dotenv

load_dotenv()

_level = getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO)

logging.basicConfig(
    level=_level,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)

logger: logging.Logger = logging.getLogger("project_swarm")
logger.setLevel(_level)
