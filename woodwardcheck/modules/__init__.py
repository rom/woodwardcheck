"""
Audit modules for WoodwardCheck.

Each module provides specific security checks for EasyGen controllers.
"""

from .base import BaseModule, CheckDefinition, Finding
from .security_checks import SecurityChecksModule
from .vulnerability_scanner import VulnerabilityScannerModule
from .config_controls import ConfigControlsModule
from .network_analysis import NetworkAnalysisModule

__all__ = [
    "BaseModule",
    "CheckDefinition",
    "Finding",
    "SecurityChecksModule",
    "VulnerabilityScannerModule",
    "ConfigControlsModule",
    "NetworkAnalysisModule",
]

# Registry of all available modules
MODULE_REGISTRY = {
    "security": SecurityChecksModule,
    "vulnerability": VulnerabilityScannerModule,
    "config": ConfigControlsModule,
    "network": NetworkAnalysisModule,
}
