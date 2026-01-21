"""
WoodwardCheck - Security Audit Tool for Woodward EasyGen Controllers

A comprehensive security auditing tool designed for Woodward EasyGen
generator controllers, with specific focus on the 3500XT model.
"""

__version__ = "1.0.0"
__author__ = "WoodwardCheck Team"
__license__ = "MIT"

from .engine import AuditEngine
from .cli import main

__all__ = ["AuditEngine", "main", "__version__"]
