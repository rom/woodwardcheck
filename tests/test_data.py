"""
Unit tests for the data module.

Tests credential file loading and data utilities.
"""

import pytest
from pathlib import Path
from unittest.mock import patch, mock_open

from woodwardcheck.data import (
    DATA_DIR,
    get_data_file_path,
    load_file_lines,
    load_default_users,
    load_default_passwords,
    DEFAULT_USERS_FILE,
    DEFAULT_PASSWORDS_FILE,
)


class TestDataDirectory:
    """Tests for data directory utilities."""

    def test_data_dir_exists(self):
        """Test that DATA_DIR points to an existing directory."""
        assert DATA_DIR.exists()
        assert DATA_DIR.is_dir()

    def test_get_data_file_path(self):
        """Test get_data_file_path returns correct path."""
        path = get_data_file_path("test.txt")
        assert path == DATA_DIR / "test.txt"

    def test_default_files_exist(self):
        """Test that default credential files exist."""
        assert DEFAULT_USERS_FILE.exists()
        assert DEFAULT_PASSWORDS_FILE.exists()


class TestLoadFileLines:
    """Tests for load_file_lines function."""

    def test_load_file_lines_basic(self, temp_dir):
        """Test basic file loading."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("line1\nline2\nline3\n")

        lines = load_file_lines(test_file)
        assert lines == ["line1", "line2", "line3"]

    def test_load_file_lines_with_comments(self, temp_dir):
        """Test loading file with comments skipped."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("# Comment\nvalue1\n# Another comment\nvalue2\n")

        lines = load_file_lines(test_file, skip_comments=True)
        assert lines == ["value1", "value2"]

    def test_load_file_lines_keep_comments(self, temp_dir):
        """Test loading file with comments kept."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("# Comment\nvalue1\n")

        lines = load_file_lines(test_file, skip_comments=False)
        assert "# Comment" in lines
        assert "value1" in lines

    def test_load_file_lines_with_empty_lines(self, temp_dir):
        """Test loading file with empty lines preserved."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("value1\n\nvalue2\n")

        lines = load_file_lines(test_file, skip_empty=False)
        assert "" in lines

    def test_load_file_lines_skip_empty_lines(self, temp_dir):
        """Test loading file with empty lines skipped."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("value1\n\nvalue2\n")

        lines = load_file_lines(test_file, skip_empty=True)
        assert "" not in lines
        assert len(lines) == 2

    def test_load_file_lines_nonexistent_file(self, temp_dir):
        """Test loading nonexistent file returns empty list."""
        test_file = temp_dir / "nonexistent.txt"

        lines = load_file_lines(test_file)
        assert lines == []

    def test_load_file_lines_preserves_whitespace_content(self, temp_dir):
        """Test that internal whitespace is preserved."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("hello world\nfoo bar\n")

        lines = load_file_lines(test_file)
        assert "hello world" in lines
        assert "foo bar" in lines

    def test_load_file_lines_strips_line_endings(self, temp_dir):
        """Test that line endings are stripped."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("line1\r\nline2\r\n")

        lines = load_file_lines(test_file)
        assert all("\r" not in line and "\n" not in line for line in lines)


class TestLoadDefaultUsers:
    """Tests for load_default_users function."""

    def test_load_default_users_from_default_file(self):
        """Test loading users from default file."""
        users = load_default_users()
        assert isinstance(users, list)
        assert len(users) > 0
        assert "admin" in users

    def test_load_default_users_from_custom_file(self, temp_dir):
        """Test loading users from custom file."""
        custom_file = temp_dir / "custom_users.txt"
        custom_file.write_text("custom_user1\ncustom_user2\n")

        users = load_default_users(custom_file)
        assert users == ["custom_user1", "custom_user2"]

    def test_load_default_users_empty_lines_skipped(self, temp_dir):
        """Test that empty usernames are skipped."""
        custom_file = temp_dir / "users.txt"
        custom_file.write_text("user1\n\nuser2\n")

        users = load_default_users(custom_file)
        assert "" not in users

    def test_load_default_users_contains_expected_users(self):
        """Test that default users file contains expected usernames."""
        users = load_default_users()
        expected_users = ["admin", "user", "operator", "woodward", "easygen"]
        for expected in expected_users:
            assert expected in users


class TestLoadDefaultPasswords:
    """Tests for load_default_passwords function."""

    def test_load_default_passwords_from_default_file(self):
        """Test loading passwords from default file."""
        passwords = load_default_passwords()
        assert isinstance(passwords, list)
        assert len(passwords) > 0

    def test_load_default_passwords_from_custom_file(self, temp_dir):
        """Test loading passwords from custom file."""
        custom_file = temp_dir / "custom_passwords.txt"
        custom_file.write_text("pass1\npass2\n")

        passwords = load_default_passwords(custom_file)
        assert passwords == ["pass1", "pass2"]

    def test_load_default_passwords_includes_empty(self, temp_dir):
        """Test that empty passwords are included."""
        custom_file = temp_dir / "passwords.txt"
        custom_file.write_text("password1\n\npassword2\n")

        passwords = load_default_passwords(custom_file)
        assert "" in passwords

    def test_load_default_passwords_contains_common_passwords(self):
        """Test that default passwords file contains common passwords."""
        passwords = load_default_passwords()
        expected_passwords = ["admin", "password", "1234"]
        for expected in expected_passwords:
            assert expected in passwords


class TestDefaultCredentialFiles:
    """Tests for the default credential file contents."""

    def test_users_file_format(self):
        """Test that users file is properly formatted."""
        users = load_default_users()
        # All users should be non-empty strings (after loading)
        for user in users:
            assert isinstance(user, str)

    def test_passwords_file_format(self):
        """Test that passwords file is properly formatted."""
        passwords = load_default_passwords()
        # All passwords should be strings (including empty)
        for password in passwords:
            assert isinstance(password, str)

    def test_users_file_has_no_duplicates(self):
        """Test that users file has no duplicate entries."""
        users = load_default_users()
        assert len(users) == len(set(users))

    def test_credential_files_are_readable(self):
        """Test that credential files can be read without errors."""
        try:
            users = load_default_users()
            passwords = load_default_passwords()
            assert users is not None
            assert passwords is not None
        except Exception as e:
            pytest.fail(f"Failed to read credential files: {e}")
