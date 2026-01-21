"""
Logging infrastructure for WoodwardCheck.

Provides structured logging with multiple output targets and formatting options.
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

# Custom log level for audit events
AUDIT_LEVEL = 25
logging.addLevelName(AUDIT_LEVEL, "AUDIT")


class AuditLogger(logging.Logger):
    """Custom logger with audit level support."""

    def audit(self, msg: str, *args, **kwargs) -> None:
        """Log an audit event."""
        if self.isEnabledFor(AUDIT_LEVEL):
            self._log(AUDIT_LEVEL, msg, args, **kwargs)


class ColoredFormatter(logging.Formatter):
    """Formatter with color support for terminal output."""

    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "AUDIT": "\033[35m",     # Magenta
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[41m",  # Red background
        "RESET": "\033[0m",
    }

    def __init__(self, fmt: Optional[str] = None, use_colors: bool = True):
        super().__init__(fmt)
        self.use_colors = use_colors

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record with optional colors."""
        if self.use_colors:
            color = self.COLORS.get(record.levelname, self.COLORS["RESET"])
            reset = self.COLORS["RESET"]
            record.levelname = f"{color}{record.levelname}{reset}"
        return super().format(record)


class AuditFileHandler(logging.FileHandler):
    """File handler specifically for audit trail logs."""

    def __init__(self, filename: str, mode: str = "a"):
        super().__init__(filename, mode)
        self.setFormatter(logging.Formatter(
            "%(asctime)s|%(levelname)s|%(name)s|%(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z"
        ))


def setup_logger(
    name: str = "woodwardcheck",
    level: int = logging.INFO,
    log_file: Optional[str] = None,
    use_colors: bool = True,
    quiet: bool = False
) -> logging.Logger:
    """
    Set up and configure the logger.

    Args:
        name: Logger name
        level: Logging level
        log_file: Optional file path for log output
        use_colors: Enable colored output
        quiet: Suppress console output

    Returns:
        Configured logger instance
    """
    logging.setLoggerClass(AuditLogger)
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Clear existing handlers
    logger.handlers.clear()

    # Console handler
    if not quiet:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(level)
        console_format = "%(asctime)s [%(levelname)s] %(message)s"
        console_handler.setFormatter(ColoredFormatter(console_format, use_colors))
        logger.addHandler(console_handler)

    # File handler
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(str(log_path))
        file_handler.setLevel(level)
        file_format = "%(asctime)s [%(levelname)s] %(name)s - %(message)s"
        file_handler.setFormatter(logging.Formatter(file_format))
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str = "woodwardcheck") -> logging.Logger:
    """Get an existing logger or create a new one."""
    return logging.getLogger(name)


def create_audit_trail(
    output_dir: str,
    target: str,
    session_id: str
) -> logging.Logger:
    """
    Create an audit trail logger for compliance purposes.

    Args:
        output_dir: Directory for audit logs
        target: Target being audited
        session_id: Unique session identifier

    Returns:
        Audit trail logger
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(".", "_").replace(":", "_")
    filename = f"audit_trail_{safe_target}_{timestamp}_{session_id}.log"

    audit_path = Path(output_dir) / filename
    audit_path.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(f"woodwardcheck.audit.{session_id}")
    logger.setLevel(AUDIT_LEVEL)
    logger.addHandler(AuditFileHandler(str(audit_path)))

    return logger
