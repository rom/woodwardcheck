"""
Audit modules for WoodwardCheck.

Each module provides specific security checks for EasyGen controllers.
Includes Woodward-specific checks for EasyGen, MicroNet, and Breaker-Control devices.
"""

from .base import BaseModule, CheckDefinition, Finding
from .security_checks import SecurityChecksModule
from .vulnerability_scanner import VulnerabilityScannerModule
from .config_controls import ConfigControlsModule
from .network_analysis import NetworkAnalysisModule
from .woodward_specific import WoodwardSpecificModule

__all__ = [
    "BaseModule",
    "CheckDefinition",
    "Finding",
    "SecurityChecksModule",
    "VulnerabilityScannerModule",
    "ConfigControlsModule",
    "NetworkAnalysisModule",
    "WoodwardSpecificModule",
]

# Registry of all available modules
MODULE_REGISTRY = {
    "security": SecurityChecksModule,
    "vulnerability": VulnerabilityScannerModule,
    "config": ConfigControlsModule,
    "network": NetworkAnalysisModule,
    "woodward": WoodwardSpecificModule,
}
