"""
Unit tests for the connection module.

Tests all connection handlers and the connection manager.
"""

import pytest
import socket
from unittest.mock import MagicMock, patch, PropertyMock

from woodwardcheck.utils.connection import (
    BaseConnection,
    ConnectionManager,
    ConnectionResult,
    FTPConnection,
    HTTPConnection,
    ModbusTCPConnection,
    SNMPConnection,
    SSHConnection,
    TelnetConnection,
    VNCConnection,
)
from woodwardcheck.utils.constants import Protocol, DEFAULT_PORTS


class TestConnectionResult:
    """Tests for ConnectionResult dataclass."""

    def test_connection_result_success(self):
        """Test successful connection result."""
        result = ConnectionResult(
            success=True,
            protocol=Protocol.HTTP,
            host="192.168.1.1",
            port=80,
            response_time=0.05,
        )
        assert result.success is True
        assert result.protocol == Protocol.HTTP
        assert result.host == "192.168.1.1"
        assert result.port == 80
        assert result.response_time == 0.05
        assert result.error is None
        assert result.metadata == {}

    def test_connection_result_failure(self):
        """Test failed connection result."""
        result = ConnectionResult(
            success=False,
            protocol=Protocol.MODBUS_TCP,
            host="192.168.1.1",
            port=502,
            error="Connection refused",
        )
        assert result.success is False
        assert result.error == "Connection refused"

    def test_connection_result_with_metadata(self):
        """Test connection result with metadata."""
        result = ConnectionResult(
            success=True,
            protocol=Protocol.VNC,
            host="192.168.1.1",
            port=5900,
            metadata={"version": "RFB 003.008", "auth_types": [1, 2]},
        )
        assert result.metadata["version"] == "RFB 003.008"
        assert 1 in result.metadata["auth_types"]


class TestModbusTCPConnection:
    """Tests for ModbusTCPConnection class."""

    def test_modbus_init(self):
        """Test ModbusTCP connection initialization."""
        conn = ModbusTCPConnection("192.168.1.1", 502, 30)
        assert conn.host == "192.168.1.1"
        assert conn.port == 502
        assert conn.timeout == 30
        assert conn._connected is False

    def test_modbus_init_defaults(self):
        """Test ModbusTCP connection with default values."""
        conn = ModbusTCPConnection("192.168.1.1")
        assert conn.port == 502
        assert conn.timeout == 30

    @patch("socket.socket")
    def test_modbus_connect_success(self, mock_socket_class):
        """Test successful Modbus connection."""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        conn = ModbusTCPConnection("192.168.1.1")
        result = conn.connect()

        assert result.success is True
        assert result.protocol == Protocol.MODBUS_TCP
        assert conn._connected is True
        mock_socket.connect.assert_called_once_with(("192.168.1.1", 502))

    @patch("socket.socket")
    def test_modbus_connect_failure(self, mock_socket_class):
        """Test failed Modbus connection."""
        mock_socket = MagicMock()
        mock_socket.connect.side_effect = socket.error("Connection refused")
        mock_socket_class.return_value = mock_socket

        conn = ModbusTCPConnection("192.168.1.1")
        result = conn.connect()

        assert result.success is False
        assert "refused" in result.error.lower()

    def test_modbus_disconnect(self):
        """Test Modbus disconnection."""
        conn = ModbusTCPConnection("192.168.1.1")
        conn._socket = MagicMock()
        conn._connected = True

        conn.disconnect()

        assert conn._connected is False
        assert conn._socket is None

    def test_modbus_is_connected(self):
        """Test is_connected method."""
        conn = ModbusTCPConnection("192.168.1.1")
        assert conn.is_connected() is False

        conn._connected = True
        conn._socket = MagicMock()
        assert conn.is_connected() is True

    def test_modbus_next_transaction_id(self):
        """Test transaction ID generation."""
        conn = ModbusTCPConnection("192.168.1.1")
        id1 = conn._next_transaction_id()
        id2 = conn._next_transaction_id()
        assert id2 == id1 + 1

    def test_modbus_transaction_id_wrap(self):
        """Test transaction ID wraps at 65536."""
        conn = ModbusTCPConnection("192.168.1.1")
        conn._transaction_id = 65535
        next_id = conn._next_transaction_id()
        assert next_id == 0

    def test_modbus_read_holding_registers_not_connected(self):
        """Test reading registers when not connected."""
        conn = ModbusTCPConnection("192.168.1.1")
        result = conn.read_holding_registers(0, 10)
        assert result is None

    def test_modbus_read_device_id_not_connected(self):
        """Test reading device ID when not connected."""
        conn = ModbusTCPConnection("192.168.1.1")
        result = conn.read_device_id()
        assert result is None


class TestHTTPConnection:
    """Tests for HTTPConnection class."""

    def test_http_init(self):
        """Test HTTP connection initialization."""
        conn = HTTPConnection("192.168.1.1", 80, 30)
        assert conn.host == "192.168.1.1"
        assert conn.port == 80
        assert conn.timeout == 30
        assert conn.use_ssl is False
        assert conn.verify_ssl is True

    def test_https_init(self):
        """Test HTTPS connection initialization."""
        conn = HTTPConnection("192.168.1.1", 443, 30, use_ssl=True)
        assert conn.use_ssl is True
        assert conn.port == 443

    @patch("urllib.request.urlopen")
    def test_http_connect_success(self, mock_urlopen):
        """Test successful HTTP connection."""
        mock_response = MagicMock()
        mock_response.getcode.return_value = 200
        mock_response.headers = {"Content-Type": "text/html"}
        mock_urlopen.return_value = mock_response

        conn = HTTPConnection("192.168.1.1")
        result = conn.connect()

        assert result.success is True
        assert result.protocol == Protocol.HTTP
        assert result.metadata["status_code"] == 200

    @patch("urllib.request.urlopen")
    def test_http_connect_failure(self, mock_urlopen):
        """Test failed HTTP connection."""
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        conn = HTTPConnection("192.168.1.1")
        result = conn.connect()

        assert result.success is False

    def test_http_disconnect(self):
        """Test HTTP disconnection."""
        conn = HTTPConnection("192.168.1.1")
        conn._connected = True
        conn.disconnect()
        assert conn._connected is False

    def test_http_is_connected(self):
        """Test HTTP is_connected method."""
        conn = HTTPConnection("192.168.1.1")
        assert conn.is_connected() is False
        conn._connected = True
        assert conn.is_connected() is True


class TestVNCConnection:
    """Tests for VNCConnection class."""

    def test_vnc_init(self):
        """Test VNC connection initialization."""
        conn = VNCConnection("192.168.1.1", 5900, 30)
        assert conn.host == "192.168.1.1"
        assert conn.port == 5900
        assert conn.timeout == 30
        assert conn._version is None
        assert conn._auth_types == []

    def test_vnc_auth_constants(self):
        """Test VNC authentication type constants."""
        assert VNCConnection.VNC_AUTH_NONE == 1
        assert VNCConnection.VNC_AUTH_VNC == 2
        assert VNCConnection.VNC_AUTH_TIGHT == 16

    @patch("socket.socket")
    def test_vnc_connect_success(self, mock_socket_class):
        """Test successful VNC connection."""
        mock_socket = MagicMock()
        mock_socket.recv.side_effect = [
            b"RFB 003.008\n",  # Version
            bytes([2, 1, 2]),  # Auth types: None(1), VNC(2)
        ]
        mock_socket_class.return_value = mock_socket

        conn = VNCConnection("192.168.1.1")
        result = conn.connect()

        assert result.success is True
        assert result.protocol == Protocol.VNC

    @patch("socket.socket")
    def test_vnc_connect_failure(self, mock_socket_class):
        """Test failed VNC connection."""
        mock_socket = MagicMock()
        mock_socket.connect.side_effect = socket.error("Connection refused")
        mock_socket_class.return_value = mock_socket

        conn = VNCConnection("192.168.1.1")
        result = conn.connect()

        assert result.success is False

    def test_vnc_get_security_info(self):
        """Test getting VNC security info."""
        conn = VNCConnection("192.168.1.1")
        conn._version = "RFB 003.008"
        conn._auth_types = [1, 2]

        info = conn.get_security_info()

        assert info["version"] == "RFB 003.008"
        assert 1 in info["auth_types"]
        assert info["no_auth_supported"] is True
        assert info["vnc_auth_supported"] is True


class TestTelnetConnection:
    """Tests for TelnetConnection class."""

    def test_telnet_init(self):
        """Test Telnet connection initialization."""
        conn = TelnetConnection("192.168.1.1", 23, 30)
        assert conn.host == "192.168.1.1"
        assert conn.port == 23
        assert conn.timeout == 30
        assert conn._banner is None

    @patch("socket.socket")
    def test_telnet_connect_success(self, mock_socket_class):
        """Test successful Telnet connection."""
        mock_socket = MagicMock()
        mock_socket.recv.return_value = b"Welcome to Telnet\r\n"
        mock_socket_class.return_value = mock_socket

        conn = TelnetConnection("192.168.1.1")
        result = conn.connect()

        assert result.success is True
        assert result.protocol == Protocol.TELNET
        assert result.metadata["cleartext_protocol"] is True

    @patch("socket.socket")
    def test_telnet_connect_failure(self, mock_socket_class):
        """Test failed Telnet connection."""
        mock_socket = MagicMock()
        mock_socket.connect.side_effect = socket.error("Connection refused")
        mock_socket_class.return_value = mock_socket

        conn = TelnetConnection("192.168.1.1")
        result = conn.connect()

        assert result.success is False

    def test_telnet_get_banner(self):
        """Test getting Telnet banner."""
        conn = TelnetConnection("192.168.1.1")
        conn._banner = "Test Banner"
        assert conn.get_banner() == "Test Banner"


class TestSSHConnection:
    """Tests for SSHConnection class."""

    def test_ssh_init(self):
        """Test SSH connection initialization."""
        conn = SSHConnection("192.168.1.1", 22, 30)
        assert conn.host == "192.168.1.1"
        assert conn.port == 22
        assert conn.timeout == 30
        assert conn._banner is None
        assert conn._server_version is None

    @patch("socket.socket")
    def test_ssh_connect_success(self, mock_socket_class):
        """Test successful SSH connection."""
        mock_socket = MagicMock()
        mock_socket.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"
        mock_socket_class.return_value = mock_socket

        conn = SSHConnection("192.168.1.1")
        result = conn.connect()

        assert result.success is True
        assert result.protocol == Protocol.SSH
        assert result.metadata["encrypted_protocol"] is True

    @patch("socket.socket")
    def test_ssh_connect_failure(self, mock_socket_class):
        """Test failed SSH connection."""
        mock_socket = MagicMock()
        mock_socket.connect.side_effect = socket.error("Connection refused")
        mock_socket_class.return_value = mock_socket

        conn = SSHConnection("192.168.1.1")
        result = conn.connect()

        assert result.success is False

    def test_ssh_get_security_info(self):
        """Test getting SSH security info."""
        conn = SSHConnection("192.168.1.1")
        conn._banner = "SSH-2.0-OpenSSH_8.9"
        conn._server_version = "OpenSSH_8.9"

        info = conn.get_security_info()

        assert info["banner"] == "SSH-2.0-OpenSSH_8.9"
        assert info["server_version"] == "OpenSSH_8.9"
        assert info["ssh1_supported"] is False


class TestFTPConnection:
    """Tests for FTPConnection class."""

    def test_ftp_init(self):
        """Test FTP connection initialization."""
        conn = FTPConnection("192.168.1.1", 21, 30)
        assert conn.host == "192.168.1.1"
        assert conn.port == 21
        assert conn.timeout == 30
        assert conn._banner is None
        assert conn._anonymous_allowed is False

    def test_ftp_constants(self):
        """Test FTP response code constants."""
        assert FTPConnection.FTP_READY == 220
        assert FTPConnection.FTP_AUTH_REQUIRED == 530
        assert FTPConnection.FTP_ANON_OK == 230
        assert FTPConnection.FTP_USER_OK == 331

    @patch("socket.socket")
    def test_ftp_connect_success(self, mock_socket_class):
        """Test successful FTP connection."""
        mock_socket = MagicMock()
        mock_socket.recv.side_effect = [
            b"220 FTP Server Ready\r\n",  # Banner
            b"331 Password required\r\n",  # USER response
            b"530 Login incorrect\r\n",  # PASS response (anonymous rejected)
        ]
        mock_socket_class.return_value = mock_socket

        conn = FTPConnection("192.168.1.1")
        result = conn.connect()

        assert result.success is True
        assert result.protocol == Protocol.FTP
        assert result.metadata["cleartext_protocol"] is True

    @patch("socket.socket")
    def test_ftp_connect_anonymous_allowed(self, mock_socket_class):
        """Test FTP with anonymous access allowed."""
        mock_socket = MagicMock()
        mock_socket.recv.side_effect = [
            b"220 FTP Server Ready\r\n",  # Banner
            b"331 Anonymous login ok\r\n",  # USER response
            b"230 Welcome\r\n",  # PASS response (anonymous accepted)
        ]
        mock_socket_class.return_value = mock_socket

        conn = FTPConnection("192.168.1.1")
        result = conn.connect()

        assert result.success is True
        assert result.metadata["anonymous_allowed"] is True

    @patch("socket.socket")
    def test_ftp_connect_failure(self, mock_socket_class):
        """Test failed FTP connection."""
        mock_socket = MagicMock()
        mock_socket.connect.side_effect = socket.error("Connection refused")
        mock_socket_class.return_value = mock_socket

        conn = FTPConnection("192.168.1.1")
        result = conn.connect()

        assert result.success is False

    def test_ftp_get_security_info(self):
        """Test getting FTP security info."""
        conn = FTPConnection("192.168.1.1")
        conn._banner = "220 FTP Server"
        conn._server_info = "FTP Server"
        conn._anonymous_allowed = True

        info = conn.get_security_info()

        assert info["banner"] == "220 FTP Server"
        assert info["anonymous_allowed"] is True
        assert info["cleartext_protocol"] is True


class TestSNMPConnection:
    """Tests for SNMPConnection class."""

    def test_snmp_init(self):
        """Test SNMP connection initialization."""
        conn = SNMPConnection("192.168.1.1", 161, 30, "public", 2)
        assert conn.host == "192.168.1.1"
        assert conn.port == 161
        assert conn.community == "public"
        assert conn.version == 2

    @patch("socket.socket")
    def test_snmp_connect_success(self, mock_socket_class):
        """Test successful SNMP connection."""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket

        conn = SNMPConnection("192.168.1.1")
        result = conn.connect()

        assert result.success is True
        assert result.protocol == Protocol.SNMP
        assert result.metadata["version"] == 2
        assert result.metadata["community"] == "public"


class TestConnectionManager:
    """Tests for ConnectionManager class."""

    def test_manager_init(self):
        """Test ConnectionManager initialization."""
        manager = ConnectionManager("192.168.1.1", 30)
        assert manager.host == "192.168.1.1"
        assert manager.timeout == 30
        assert manager._connections == {}

    def test_manager_init_with_custom_ports(self):
        """Test ConnectionManager with custom ports."""
        custom_ports = {Protocol.HTTP: 8080, Protocol.VNC: 5901}
        manager = ConnectionManager("192.168.1.1", 30, custom_ports)
        assert manager._custom_ports == custom_ports

    def test_manager_get_port_default(self):
        """Test getting default port."""
        manager = ConnectionManager("192.168.1.1")
        assert manager.get_port(Protocol.HTTP) == 80
        assert manager.get_port(Protocol.MODBUS_TCP) == 502

    def test_manager_get_port_custom(self):
        """Test getting custom port."""
        manager = ConnectionManager(
            "192.168.1.1",
            custom_ports={Protocol.HTTP: 8080},
        )
        assert manager.get_port(Protocol.HTTP) == 8080
        assert manager.get_port(Protocol.HTTPS) == 443  # Default

    def test_manager_set_custom_port(self):
        """Test setting custom port."""
        manager = ConnectionManager("192.168.1.1")
        manager.set_custom_port(Protocol.VNC, 5901)
        assert manager.get_port(Protocol.VNC) == 5901

    def test_manager_get_connection_modbus(self):
        """Test getting Modbus connection."""
        manager = ConnectionManager("192.168.1.1")
        conn = manager.get_connection(Protocol.MODBUS_TCP)
        assert isinstance(conn, ModbusTCPConnection)

    def test_manager_get_connection_http(self):
        """Test getting HTTP connection."""
        manager = ConnectionManager("192.168.1.1")
        conn = manager.get_connection(Protocol.HTTP)
        assert isinstance(conn, HTTPConnection)

    def test_manager_get_connection_https(self):
        """Test getting HTTPS connection."""
        manager = ConnectionManager("192.168.1.1")
        conn = manager.get_connection(Protocol.HTTPS)
        assert isinstance(conn, HTTPConnection)
        assert conn.use_ssl is True

    def test_manager_get_connection_vnc(self):
        """Test getting VNC connection."""
        manager = ConnectionManager("192.168.1.1")
        conn = manager.get_connection(Protocol.VNC)
        assert isinstance(conn, VNCConnection)

    def test_manager_get_connection_telnet(self):
        """Test getting Telnet connection."""
        manager = ConnectionManager("192.168.1.1")
        conn = manager.get_connection(Protocol.TELNET)
        assert isinstance(conn, TelnetConnection)

    def test_manager_get_connection_ssh(self):
        """Test getting SSH connection."""
        manager = ConnectionManager("192.168.1.1")
        conn = manager.get_connection(Protocol.SSH)
        assert isinstance(conn, SSHConnection)

    def test_manager_get_connection_ftp(self):
        """Test getting FTP connection."""
        manager = ConnectionManager("192.168.1.1")
        conn = manager.get_connection(Protocol.FTP)
        assert isinstance(conn, FTPConnection)

    def test_manager_get_connection_snmp(self):
        """Test getting SNMP connection."""
        manager = ConnectionManager("192.168.1.1")
        conn = manager.get_connection(Protocol.SNMP)
        assert isinstance(conn, SNMPConnection)

    def test_manager_connection_caching(self):
        """Test that connections are cached."""
        manager = ConnectionManager("192.168.1.1")
        conn1 = manager.get_connection(Protocol.HTTP)
        conn2 = manager.get_connection(Protocol.HTTP)
        assert conn1 is conn2

    def test_manager_close_all(self):
        """Test closing all connections."""
        manager = ConnectionManager("192.168.1.1")
        manager.get_connection(Protocol.HTTP)
        manager.get_connection(Protocol.VNC)

        manager.close_all()

        assert manager._connections == {}

    @patch.object(ModbusTCPConnection, "connect")
    def test_manager_test_connectivity(self, mock_connect):
        """Test testing connectivity."""
        mock_connect.return_value = ConnectionResult(
            success=True,
            protocol=Protocol.MODBUS_TCP,
            host="192.168.1.1",
            port=502,
        )

        manager = ConnectionManager("192.168.1.1")
        result = manager.test_connectivity(Protocol.MODBUS_TCP)

        assert result.success is True
        mock_connect.assert_called_once()

    def test_manager_context_manager(self):
        """Test connection context manager."""
        manager = ConnectionManager("192.168.1.1")

        with patch.object(ModbusTCPConnection, "connect"):
            with patch.object(ModbusTCPConnection, "disconnect") as mock_disconnect:
                with manager.connection(Protocol.MODBUS_TCP) as conn:
                    assert isinstance(conn, ModbusTCPConnection)

                mock_disconnect.assert_called()
