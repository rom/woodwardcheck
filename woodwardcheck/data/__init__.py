"""
Data files for WoodwardCheck.

Contains default credentials and other reference data used by scanners and checkers.
"""

import os
from pathlib import Path
from typing import List, Optional


# Path to the data directory
DATA_DIR = Path(__file__).parent


def get_data_file_path(filename: str) -> Path:
    """Get the full path to a data file."""
    return DATA_DIR / filename


def load_file_lines(filepath: Path, skip_comments: bool = True, skip_empty: bool = False) -> List[str]:
    """
    Load lines from a file, optionally skipping comments and empty lines.

    Args:
        filepath: Path to the file to load
        skip_comments: If True, skip lines starting with #
        skip_empty: If True, skip empty lines (default False to allow empty passwords)

    Returns:
        List of lines from the file
    """
    lines = []
    if not filepath.exists():
        return lines

    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.rstrip('\n\r')
            if skip_comments and line.startswith('#'):
                continue
            if skip_empty and not line:
                continue
            lines.append(line)

    return lines


def load_default_users(filepath: Optional[Path] = None) -> List[str]:
    """
    Load default usernames from file.

    Args:
        filepath: Optional custom path to users file

    Returns:
        List of usernames
    """
    if filepath is None:
        filepath = get_data_file_path('default_users.txt')
    return load_file_lines(filepath, skip_comments=True, skip_empty=True)


def load_default_passwords(filepath: Optional[Path] = None) -> List[str]:
    """
    Load default passwords from file.
    Empty passwords are included as they are common on ICS devices.

    Args:
        filepath: Optional custom path to passwords file

    Returns:
        List of passwords (including empty string if present)
    """
    if filepath is None:
        filepath = get_data_file_path('default_passwords.txt')
    return load_file_lines(filepath, skip_comments=True, skip_empty=False)


# Default file paths
DEFAULT_USERS_FILE = get_data_file_path('default_users.txt')
DEFAULT_PASSWORDS_FILE = get_data_file_path('default_passwords.txt')
