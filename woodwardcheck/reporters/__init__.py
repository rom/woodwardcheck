"""
Report generators for WoodwardCheck.

Provides multiple output formats for audit results.
"""

from .base import BaseReporter, ReportData
from .html_reporter import HTMLReporter
from .json_reporter import JSONReporter
from .rtf_reporter import RTFReporter
from .markdown_reporter import MarkdownReporter
from .text_reporter import TextReporter

__all__ = [
    "BaseReporter",
    "ReportData",
    "HTMLReporter",
    "JSONReporter",
    "RTFReporter",
    "MarkdownReporter",
    "TextReporter",
]

# Registry of available reporters
REPORTER_REGISTRY = {
    "html": HTMLReporter,
    "json": JSONReporter,
    "rtf": RTFReporter,
    "markdown": MarkdownReporter,
    "md": MarkdownReporter,
    "text": TextReporter,
    "txt": TextReporter,
}


def get_reporter(format_name: str) -> type:
    """Get reporter class by format name."""
    format_lower = format_name.lower()
    if format_lower not in REPORTER_REGISTRY:
        raise ValueError(f"Unknown report format: {format_name}. "
                        f"Available formats: {', '.join(REPORTER_REGISTRY.keys())}")
    return REPORTER_REGISTRY[format_lower]
