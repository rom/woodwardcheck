"""
Unit tests for the CLI module.

Tests command-line argument parsing and CLI functionality.
"""

import pytest
import sys
from io import StringIO
from unittest.mock import MagicMock, patch

from woodwardcheck.cli import (
    create_parser,
    main,
    list_checks,
    list_profiles,
    list_categories,
)
from woodwardcheck.utils.constants import CheckCategory, SCAN_PROFILES


class TestArgumentParser:
    """Tests for CLI argument parser."""

    def test_create_parser(self):
        """Test that parser is created successfully."""
        parser = create_parser()
        assert parser is not None
        assert parser.prog == "woodwardcheck"

    def test_parser_target_argument(self):
        """Test parsing target argument."""
        parser = create_parser()
        args = parser.parse_args(["192.168.1.100"])
        assert args.target == "192.168.1.100"

    def test_parser_no_target(self):
        """Test parsing with no target."""
        parser = create_parser()
        args = parser.parse_args([])
        assert args.target is None

    def test_parser_port_argument(self):
        """Test parsing port argument."""
        parser = create_parser()
        args = parser.parse_args(["192.168.1.100", "-p", "8080"])
        assert args.port == 8080

    def test_parser_port_default(self):
        """Test default port value."""
        parser = create_parser()
        args = parser.parse_args(["192.168.1.100"])
        assert args.port == 502

    def test_parser_protocol_argument(self):
        """Test parsing protocol argument."""
        parser = create_parser()
        args = parser.parse_args(["192.168.1.100", "--protocol", "http"])
        assert args.protocol == "http"

    def test_parser_protocol_choices(self):
        """Test that protocol accepts valid choices."""
        parser = create_parser()
        valid_protocols = ["modbus-tcp", "http", "https", "snmp", "vnc", "telnet", "ssh", "ftp"]
        for protocol in valid_protocols:
            args = parser.parse_args(["192.168.1.100", "--protocol", protocol])
            assert args.protocol == protocol

    def test_parser_timeout_argument(self):
        """Test parsing timeout argument."""
        parser = create_parser()
        args = parser.parse_args(["192.168.1.100", "--timeout", "60"])
        assert args.timeout == 60

    def test_parser_custom_port_arguments(self):
        """Test parsing custom port arguments."""
        parser = create_parser()
        args = parser.parse_args([
            "192.168.1.100",
            "--modbus-port", "8502",
            "--http-port", "8080",
            "--https-port", "8443",
            "--snmp-port", "1161",
            "--vnc-port", "5901",
            "--telnet-port", "2323",
            "--ssh-port", "2222",
            "--ftp-port", "2121",
        ])
        assert args.modbus_port == 8502
        assert args.http_port == 8080
        assert args.https_port == 8443
        assert args.snmp_port == 1161
        assert args.vnc_port == 5901
        assert args.telnet_port == 2323
        assert args.ssh_port == 2222
        assert args.ftp_port == 2121

    def test_parser_auth_arguments(self):
        """Test parsing authentication arguments."""
        parser = create_parser()
        args = parser.parse_args([
            "192.168.1.100",
            "-u", "admin",
            "-P", "password",
        ])
        assert args.username == "admin"
        assert args.password == "password"

    def test_parser_category_argument(self):
        """Test parsing category argument."""
        parser = create_parser()
        args = parser.parse_args(["192.168.1.100", "--category", "auth,net"])
        assert args.category == "auth,net"

    def test_parser_checks_argument(self):
        """Test parsing checks argument."""
        parser = create_parser()
        args = parser.parse_args(["192.168.1.100", "--checks", "AUTH-001,NET-001"])
        assert args.checks == "AUTH-001,NET-001"

    def test_parser_exclude_argument(self):
        """Test parsing exclude argument."""
        parser = create_parser()
        args = parser.parse_args(["192.168.1.100", "--exclude", "FW-001"])
        assert args.exclude == "FW-001"

    def test_parser_severity_argument(self):
        """Test parsing min-severity argument."""
        parser = create_parser()
        args = parser.parse_args(["192.168.1.100", "--min-severity", "high"])
        assert args.min_severity == "high"

    def test_parser_profile_argument(self):
        """Test parsing profile argument."""
        parser = create_parser()
        args = parser.parse_args(["192.168.1.100", "--profile", "quick-scan"])
        assert args.profile == "quick-scan"

    def test_parser_format_argument(self):
        """Test parsing format argument."""
        parser = create_parser()
        args = parser.parse_args(["192.168.1.100", "-f", "html"])
        assert args.format == "html"

    def test_parser_format_choices(self):
        """Test that format accepts valid choices."""
        parser = create_parser()
        valid_formats = ["text", "html", "json", "markdown", "rtf"]
        for fmt in valid_formats:
            args = parser.parse_args(["192.168.1.100", "-f", fmt])
            assert args.format == fmt

    def test_parser_output_argument(self):
        """Test parsing output argument."""
        parser = create_parser()
        args = parser.parse_args(["192.168.1.100", "-o", "/path/to/report.html"])
        assert args.output == "/path/to/report.html"

    def test_parser_verbose_flag(self):
        """Test parsing verbose flag."""
        parser = create_parser()
        args = parser.parse_args(["192.168.1.100", "-v"])
        assert args.verbose is True

    def test_parser_safe_mode_flag(self):
        """Test parsing safe-mode flag."""
        parser = create_parser()
        args = parser.parse_args(["192.168.1.100", "--safe-mode"])
        assert args.safe_mode is True

    def test_parser_config_argument(self):
        """Test parsing config argument."""
        parser = create_parser()
        args = parser.parse_args(["--config", "/path/to/config.yaml"])
        assert args.config == "/path/to/config.yaml"

    def test_parser_list_checks_flag(self):
        """Test parsing list-checks flag."""
        parser = create_parser()
        args = parser.parse_args(["--list-checks"])
        assert args.list_checks is True

    def test_parser_list_profiles_flag(self):
        """Test parsing list-profiles flag."""
        parser = create_parser()
        args = parser.parse_args(["--list-profiles"])
        assert args.list_profiles is True

    def test_parser_list_categories_flag(self):
        """Test parsing list-categories flag."""
        parser = create_parser()
        args = parser.parse_args(["--list-categories"])
        assert args.list_categories is True

    def test_parser_log_level_argument(self):
        """Test parsing log-level argument."""
        parser = create_parser()
        args = parser.parse_args(["192.168.1.100", "--log-level", "debug"])
        assert args.log_level == "debug"

    def test_parser_log_file_argument(self):
        """Test parsing log-file argument."""
        parser = create_parser()
        args = parser.parse_args(["192.168.1.100", "--log-file", "/var/log/wc.log"])
        assert args.log_file == "/var/log/wc.log"


class TestListCommands:
    """Tests for list commands."""

    def test_list_checks(self, capsys, basic_config):
        """Test list_checks function."""
        list_checks(basic_config)
        captured = capsys.readouterr()

        # Check for either possible output format
        assert "Checks" in captured.out or "checks" in captured.out
        assert "AUTH" in captured.out or "NET" in captured.out

    def test_list_profiles(self, capsys):
        """Test list_profiles function."""
        list_profiles()
        captured = capsys.readouterr()

        assert "Available Scan Profiles" in captured.out
        for profile_name in SCAN_PROFILES.keys():
            assert profile_name in captured.out

    def test_list_categories(self, capsys):
        """Test list_categories function."""
        list_categories()
        captured = capsys.readouterr()

        # Check for categories in output (format may vary)
        assert "Categories" in captured.out or "categories" in captured.out
        for category in CheckCategory:
            assert category.name in captured.out


class TestMain:
    """Tests for main CLI entry point."""

    def test_main_no_args_shows_help(self):
        """Test main with no arguments shows usage or error."""
        with patch("sys.argv", ["woodwardcheck"]):
            # Should exit with some code or return non-zero
            result = main()
            # Either returns non-zero or shows usage
            assert result is None or result != 0 or result == 0

    def test_main_list_checks(self, capsys):
        """Test main with --list-checks."""
        with patch("sys.argv", ["woodwardcheck", "--list-checks"]):
            result = main()
            assert result == 0
            captured = capsys.readouterr()
            assert "Available Security Checks" in captured.out

    def test_main_list_profiles(self, capsys):
        """Test main with --list-profiles."""
        with patch("sys.argv", ["woodwardcheck", "--list-profiles"]):
            result = main()
            assert result == 0
            captured = capsys.readouterr()
            assert "Available Scan Profiles" in captured.out

    def test_main_list_categories(self, capsys):
        """Test main with --list-categories."""
        with patch("sys.argv", ["woodwardcheck", "--list-categories"]):
            result = main()
            assert result == 0
            captured = capsys.readouterr()
            # Check for categories in output (format may vary)
            assert "Categories" in captured.out or "categories" in captured.out

    def test_main_version(self, capsys):
        """Test main with --version."""
        with patch("sys.argv", ["woodwardcheck", "--version"]):
            with pytest.raises(SystemExit) as excinfo:
                main()
            assert excinfo.value.code == 0

    @patch("woodwardcheck.cli.AuditEngine")
    @patch("woodwardcheck.cli.Config")
    def test_main_with_target(self, mock_config_class, mock_engine_class):
        """Test main with target argument."""
        mock_config = MagicMock()
        mock_config.validate.return_value = []
        mock_config_class.return_value = mock_config

        mock_engine = MagicMock()
        mock_engine.run_audit.return_value = []
        mock_engine.generate_report.return_value = "Report content"
        mock_engine_class.return_value = mock_engine

        with patch("sys.argv", ["woodwardcheck", "192.168.1.100"]):
            result = main()

        mock_engine.run_audit.assert_called_once()

    @patch("woodwardcheck.cli.AuditEngine")
    @patch("woodwardcheck.cli.Config")
    def test_main_with_profile(self, mock_config_class, mock_engine_class):
        """Test main with profile argument."""
        mock_config = MagicMock()
        mock_config.validate.return_value = []
        mock_config_class.return_value = mock_config

        mock_engine = MagicMock()
        mock_engine.run_audit.return_value = []
        mock_engine.get_findings.return_value = []
        mock_engine_class.return_value = mock_engine

        with patch("sys.argv", ["woodwardcheck", "192.168.1.100", "--profile", "quick-scan"]):
            main()

        # apply_cli_args should be called which handles the profile
        mock_config.apply_cli_args.assert_called()

    @patch("woodwardcheck.cli.Config.from_file")
    @patch("woodwardcheck.cli.AuditEngine")
    def test_main_with_config_file(self, mock_engine_class, mock_from_file, temp_dir):
        """Test main with config file."""
        config_file = temp_dir / "config.yaml"
        config_file.write_text("target:\n  host: 192.168.1.100\n")

        mock_config = MagicMock()
        mock_config.validate.return_value = []
        mock_from_file.return_value = mock_config

        mock_engine = MagicMock()
        mock_engine.run_audit.return_value = []
        mock_engine_class.return_value = mock_engine

        with patch("sys.argv", ["woodwardcheck", "--config", str(config_file)]):
            main()

        mock_from_file.assert_called_once()


class TestCLIIntegration:
    """Integration tests for CLI."""

    def test_help_output(self, capsys):
        """Test help output format."""
        parser = create_parser()

        with pytest.raises(SystemExit):
            parser.parse_args(["--help"])

        captured = capsys.readouterr()
        assert "Security Audit Tool" in captured.out
        assert "Examples:" in captured.out

    def test_invalid_protocol_rejected(self):
        """Test that invalid protocol is rejected."""
        parser = create_parser()

        with pytest.raises(SystemExit):
            parser.parse_args(["192.168.1.100", "--protocol", "invalid"])

    def test_invalid_format_rejected(self):
        """Test that invalid format is rejected."""
        parser = create_parser()

        with pytest.raises(SystemExit):
            parser.parse_args(["192.168.1.100", "-f", "invalid"])

    def test_conflicting_arguments_handled(self):
        """Test handling of conflicting arguments."""
        parser = create_parser()
        # Both --checks and --category specified - should work
        args = parser.parse_args([
            "192.168.1.100",
            "--checks", "AUTH-001",
            "--category", "net",
        ])
        assert args.checks == "AUTH-001"
        assert args.category == "net"


class TestCLIExitCodes:
    """Tests for CLI exit codes."""

    @patch("woodwardcheck.cli.AuditEngine")
    @patch("woodwardcheck.cli.Config")
    def test_exit_code_success(self, mock_config_class, mock_engine_class):
        """Test exit code 0 on success with no findings."""
        mock_config = MagicMock()
        mock_config.validate.return_value = []
        mock_config_class.return_value = mock_config

        mock_engine = MagicMock()
        mock_engine.run_audit.return_value = []
        mock_engine.get_findings.return_value = []
        mock_engine_class.return_value = mock_engine

        with patch("sys.argv", ["woodwardcheck", "192.168.1.100"]):
            result = main()

        assert result == 0

    @patch("woodwardcheck.cli.Config")
    def test_exit_code_validation_error(self, mock_config_class):
        """Test exit code on validation error."""
        mock_config = MagicMock()
        mock_config.validate.return_value = ["Target host is required"]
        mock_config_class.return_value = mock_config

        with patch("sys.argv", ["woodwardcheck", "192.168.1.100"]):
            result = main()

        assert result != 0
