"""
Connection management for WoodwardCheck.

Handles connections to EasyGen devices via various protocols.
"""

import socket
import ssl
import struct
import time
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Dict, Generator, List, Optional, Tuple

from .constants import Protocol, DEFAULT_PORTS, EASYGEN_3500XT_REGISTERS
from .logger import get_logger


@dataclass
class ConnectionResult:
    """Result of a connection attempt."""
    success: bool
    protocol: Protocol
    host: str
    port: int
    error: Optional[str] = None
    response_time: Optional[float] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class BaseConnection(ABC):
    """Abstract base class for protocol connections."""

    def __init__(self, host: str, port: int, timeout: int = 30):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.logger = get_logger("woodwardcheck.connection")
        self._connected = False

    @abstractmethod
    def connect(self) -> ConnectionResult:
        """Establish connection to target."""
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """Close connection."""
        pass

    @abstractmethod
    def is_connected(self) -> bool:
        """Check if connection is active."""
        pass

    @property
    def connected(self) -> bool:
        return self._connected


class ModbusTCPConnection(BaseConnection):
    """Modbus TCP connection handler."""

    MODBUS_PORT = 502
    PROTOCOL_ID = 0
    UNIT_ID = 1

    def __init__(self, host: str, port: int = 502, timeout: int = 30):
        super().__init__(host, port, timeout)
        self._socket: Optional[socket.socket] = None
        self._transaction_id = 0

    def connect(self) -> ConnectionResult:
        """Establish Modbus TCP connection."""
        start_time = time.time()
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(self.timeout)
            self._socket.connect((self.host, self.port))
            self._connected = True
            response_time = time.time() - start_time

            self.logger.debug(f"Modbus TCP connection established to {self.host}:{self.port}")

            return ConnectionResult(
                success=True,
                protocol=Protocol.MODBUS_TCP,
                host=self.host,
                port=self.port,
                response_time=response_time,
            )
        except socket.error as e:
            self.logger.error(f"Modbus TCP connection failed: {e}")
            return ConnectionResult(
                success=False,
                protocol=Protocol.MODBUS_TCP,
                host=self.host,
                port=self.port,
                error=str(e),
            )

    def disconnect(self) -> None:
        """Close Modbus TCP connection."""
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None
        self._connected = False

    def is_connected(self) -> bool:
        """Check if Modbus TCP connection is active."""
        return self._connected and self._socket is not None

    def _next_transaction_id(self) -> int:
        """Get next transaction ID."""
        self._transaction_id = (self._transaction_id + 1) % 65536
        return self._transaction_id

    def read_holding_registers(
        self,
        address: int,
        count: int = 1,
        unit_id: int = 1
    ) -> Optional[List[int]]:
        """
        Read holding registers from the device.

        Args:
            address: Starting register address
            count: Number of registers to read
            unit_id: Modbus unit ID

        Returns:
            List of register values or None on error
        """
        if not self.is_connected():
            self.logger.error("Not connected")
            return None

        try:
            # Build Modbus request
            transaction_id = self._next_transaction_id()
            function_code = 3  # Read Holding Registers

            # MBAP Header + PDU
            request = struct.pack(
                ">HHHBBHH",
                transaction_id,      # Transaction ID
                self.PROTOCOL_ID,    # Protocol ID
                6,                   # Length
                unit_id,             # Unit ID
                function_code,       # Function Code
                address,             # Starting Address
                count,               # Quantity of Registers
            )

            self._socket.send(request)

            # Receive response
            response = self._socket.recv(256)
            if len(response) < 9:
                return None

            # Parse response
            resp_transaction_id, proto_id, length, resp_unit_id, resp_func = struct.unpack(
                ">HHHBB", response[:8]
            )

            if resp_func == function_code:
                byte_count = response[8]
                values = []
                for i in range(count):
                    offset = 9 + i * 2
                    value = struct.unpack(">H", response[offset:offset + 2])[0]
                    values.append(value)
                return values
            elif resp_func == function_code + 0x80:
                # Exception response
                exception_code = response[8]
                self.logger.error(f"Modbus exception: {exception_code}")
                return None

        except Exception as e:
            self.logger.error(f"Error reading registers: {e}")
            return None

    def read_device_id(self) -> Optional[Dict[str, str]]:
        """
        Read device identification using Modbus function 43/14.

        Returns:
            Dictionary with device information or None on error
        """
        if not self.is_connected():
            return None

        try:
            # Build Read Device Identification request
            transaction_id = self._next_transaction_id()

            request = struct.pack(
                ">HHHBBBBB",
                transaction_id,
                self.PROTOCOL_ID,
                5,      # Length
                1,      # Unit ID
                43,     # Function Code (Encapsulated Interface Transport)
                14,     # MEI Type (Read Device Identification)
                1,      # Read Device ID code (basic)
                0,      # Object ID
            )

            self._socket.send(request)
            response = self._socket.recv(256)

            if len(response) > 10:
                # Parse device identification response
                device_info = {}
                # Simplified parsing - actual implementation would be more complex
                return device_info

        except Exception as e:
            self.logger.error(f"Error reading device ID: {e}")

        return None


class HTTPConnection(BaseConnection):
    """HTTP/HTTPS connection handler for EasyGen web interface."""

    def __init__(
        self,
        host: str,
        port: int = 80,
        timeout: int = 30,
        use_ssl: bool = False,
        verify_ssl: bool = True
    ):
        super().__init__(host, port, timeout)
        self.use_ssl = use_ssl
        self.verify_ssl = verify_ssl
        self._session = None

    def connect(self) -> ConnectionResult:
        """Test HTTP connection to target."""
        import urllib.request
        import urllib.error

        start_time = time.time()
        scheme = "https" if self.use_ssl else "http"
        url = f"{scheme}://{self.host}:{self.port}/"

        try:
            context = None
            if self.use_ssl and not self.verify_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            request = urllib.request.Request(url, method="HEAD")
            request.add_header("User-Agent", "WoodwardCheck/1.0")

            response = urllib.request.urlopen(
                request,
                timeout=self.timeout,
                context=context
            )

            response_time = time.time() - start_time
            self._connected = True

            return ConnectionResult(
                success=True,
                protocol=Protocol.HTTPS if self.use_ssl else Protocol.HTTP,
                host=self.host,
                port=self.port,
                response_time=response_time,
                metadata={
                    "status_code": response.getcode(),
                    "headers": dict(response.headers),
                },
            )
        except urllib.error.URLError as e:
            return ConnectionResult(
                success=False,
                protocol=Protocol.HTTPS if self.use_ssl else Protocol.HTTP,
                host=self.host,
                port=self.port,
                error=str(e),
            )

    def disconnect(self) -> None:
        """Close HTTP connection."""
        self._connected = False

    def is_connected(self) -> bool:
        """HTTP is stateless, so we check if last connect was successful."""
        return self._connected

    def get(self, path: str) -> Optional[Tuple[int, Dict, bytes]]:
        """
        Perform HTTP GET request.

        Returns:
            Tuple of (status_code, headers, body) or None on error
        """
        import urllib.request
        import urllib.error

        scheme = "https" if self.use_ssl else "http"
        url = f"{scheme}://{self.host}:{self.port}{path}"

        try:
            context = None
            if self.use_ssl and not self.verify_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            request = urllib.request.Request(url)
            request.add_header("User-Agent", "WoodwardCheck/1.0")

            response = urllib.request.urlopen(
                request,
                timeout=self.timeout,
                context=context
            )

            return (
                response.getcode(),
                dict(response.headers),
                response.read()
            )
        except urllib.error.HTTPError as e:
            return (e.code, dict(e.headers), e.read())
        except Exception as e:
            self.logger.error(f"HTTP GET error: {e}")
            return None


class SNMPConnection(BaseConnection):
    """SNMP connection handler."""

    def __init__(
        self,
        host: str,
        port: int = 161,
        timeout: int = 30,
        community: str = "public",
        version: int = 2
    ):
        super().__init__(host, port, timeout)
        self.community = community
        self.version = version
        self._socket: Optional[socket.socket] = None

    def connect(self) -> ConnectionResult:
        """Test SNMP connectivity."""
        start_time = time.time()
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.settimeout(self.timeout)

            # Send a simple SNMP GET for sysDescr
            # This is a simplified implementation
            self._connected = True
            response_time = time.time() - start_time

            return ConnectionResult(
                success=True,
                protocol=Protocol.SNMP,
                host=self.host,
                port=self.port,
                response_time=response_time,
                metadata={"version": self.version, "community": self.community},
            )
        except socket.error as e:
            return ConnectionResult(
                success=False,
                protocol=Protocol.SNMP,
                host=self.host,
                port=self.port,
                error=str(e),
            )

    def disconnect(self) -> None:
        """Close SNMP connection."""
        if self._socket:
            self._socket.close()
            self._socket = None
        self._connected = False

    def is_connected(self) -> bool:
        """Check SNMP connection status."""
        return self._connected


class VNCConnection(BaseConnection):
    """VNC connection handler for security auditing."""

    # VNC authentication types
    VNC_AUTH_NONE = 1
    VNC_AUTH_VNC = 2
    VNC_AUTH_TIGHT = 16
    VNC_AUTH_ULTRA = 17

    def __init__(
        self,
        host: str,
        port: int = 5900,
        timeout: int = 30
    ):
        super().__init__(host, port, timeout)
        self._socket: Optional[socket.socket] = None
        self._version: Optional[str] = None
        self._auth_types: List[int] = []

    def connect(self) -> ConnectionResult:
        """Test VNC connectivity and gather security information."""
        start_time = time.time()
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(self.timeout)
            self._socket.connect((self.host, self.port))

            # Read VNC protocol version
            version_data = self._socket.recv(12)
            if version_data:
                self._version = version_data.decode("utf-8", errors="ignore").strip()

            # Send our version response
            self._socket.send(b"RFB 003.008\n")

            # Read authentication types
            try:
                auth_data = self._socket.recv(256)
                if len(auth_data) > 0:
                    num_auth = auth_data[0]
                    self._auth_types = list(auth_data[1:num_auth + 1])
            except Exception:
                pass

            self._connected = True
            response_time = time.time() - start_time

            return ConnectionResult(
                success=True,
                protocol=Protocol.VNC,
                host=self.host,
                port=self.port,
                response_time=response_time,
                metadata={
                    "version": self._version,
                    "auth_types": self._auth_types,
                    "no_auth_required": self.VNC_AUTH_NONE in self._auth_types,
                },
            )
        except socket.error as e:
            return ConnectionResult(
                success=False,
                protocol=Protocol.VNC,
                host=self.host,
                port=self.port,
                error=str(e),
            )

    def disconnect(self) -> None:
        """Close VNC connection."""
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None
        self._connected = False

    def is_connected(self) -> bool:
        """Check VNC connection status."""
        return self._connected and self._socket is not None

    def get_security_info(self) -> Dict[str, Any]:
        """Get VNC security information."""
        return {
            "version": self._version,
            "auth_types": self._auth_types,
            "no_auth_supported": self.VNC_AUTH_NONE in self._auth_types,
            "vnc_auth_supported": self.VNC_AUTH_VNC in self._auth_types,
        }


class TelnetConnection(BaseConnection):
    """Telnet connection handler for security auditing."""

    def __init__(
        self,
        host: str,
        port: int = 23,
        timeout: int = 30
    ):
        super().__init__(host, port, timeout)
        self._socket: Optional[socket.socket] = None
        self._banner: Optional[str] = None

    def connect(self) -> ConnectionResult:
        """Test Telnet connectivity."""
        start_time = time.time()
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(self.timeout)
            self._socket.connect((self.host, self.port))

            # Try to grab banner
            try:
                self._socket.settimeout(3.0)
                # Send empty data to trigger banner
                banner_data = self._socket.recv(1024)
                # Filter out telnet negotiation bytes
                self._banner = "".join(
                    chr(b) for b in banner_data
                    if 32 <= b <= 126 or b in (10, 13)
                ).strip()
            except Exception:
                pass

            self._connected = True
            response_time = time.time() - start_time

            return ConnectionResult(
                success=True,
                protocol=Protocol.TELNET,
                host=self.host,
                port=self.port,
                response_time=response_time,
                metadata={
                    "banner": self._banner,
                    "cleartext_protocol": True,
                },
            )
        except socket.error as e:
            return ConnectionResult(
                success=False,
                protocol=Protocol.TELNET,
                host=self.host,
                port=self.port,
                error=str(e),
            )

    def disconnect(self) -> None:
        """Close Telnet connection."""
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None
        self._connected = False

    def is_connected(self) -> bool:
        """Check Telnet connection status."""
        return self._connected and self._socket is not None

    def get_banner(self) -> Optional[str]:
        """Get the captured banner."""
        return self._banner


class SSHConnection(BaseConnection):
    """SSH connection handler for security auditing."""

    def __init__(
        self,
        host: str,
        port: int = 22,
        timeout: int = 30
    ):
        super().__init__(host, port, timeout)
        self._socket: Optional[socket.socket] = None
        self._banner: Optional[str] = None
        self._server_version: Optional[str] = None
        self._key_exchange_init: Optional[bytes] = None

    def connect(self) -> ConnectionResult:
        """Test SSH connectivity and gather security information."""
        start_time = time.time()
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(self.timeout)
            self._socket.connect((self.host, self.port))

            # Read SSH version banner
            try:
                self._socket.settimeout(5.0)
                banner_data = self._socket.recv(256)
                self._banner = banner_data.decode("utf-8", errors="ignore").strip()

                # Parse SSH version
                if self._banner.startswith("SSH-"):
                    parts = self._banner.split("-")
                    if len(parts) >= 3:
                        self._server_version = parts[2].split()[0] if " " in parts[2] else parts[2]
            except Exception:
                pass

            self._connected = True
            response_time = time.time() - start_time

            # Determine if SSH-1 is supported (insecure)
            ssh1_supported = self._banner and "SSH-1" in self._banner if self._banner else False

            return ConnectionResult(
                success=True,
                protocol=Protocol.SSH,
                host=self.host,
                port=self.port,
                response_time=response_time,
                metadata={
                    "banner": self._banner,
                    "server_version": self._server_version,
                    "ssh1_supported": ssh1_supported,
                    "encrypted_protocol": True,
                },
            )
        except socket.error as e:
            return ConnectionResult(
                success=False,
                protocol=Protocol.SSH,
                host=self.host,
                port=self.port,
                error=str(e),
            )

    def disconnect(self) -> None:
        """Close SSH connection."""
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None
        self._connected = False

    def is_connected(self) -> bool:
        """Check SSH connection status."""
        return self._connected and self._socket is not None

    def get_security_info(self) -> Dict[str, Any]:
        """Get SSH security information."""
        return {
            "banner": self._banner,
            "server_version": self._server_version,
            "ssh1_supported": self._banner and "SSH-1" in self._banner if self._banner else False,
        }


class ConnectionManager:
    """Manager for handling multiple protocol connections."""

    def __init__(self, host: str, timeout: int = 30, custom_ports: Optional[Dict[Protocol, int]] = None):
        self.host = host
        self.timeout = timeout
        self.logger = get_logger("woodwardcheck.connection")
        self._connections: Dict[Protocol, BaseConnection] = {}
        self._custom_ports = custom_ports or {}

    def get_port(self, protocol: Protocol) -> int:
        """Get port for protocol, using custom port if configured."""
        if protocol in self._custom_ports:
            return self._custom_ports[protocol]
        return DEFAULT_PORTS.get(protocol, 502)

    def set_custom_port(self, protocol: Protocol, port: int) -> None:
        """Set a custom port for a protocol."""
        self._custom_ports[protocol] = port
        # Clear cached connection if port changed
        if protocol in self._connections:
            self._connections[protocol].disconnect()
            del self._connections[protocol]

    def get_connection(self, protocol: Protocol) -> BaseConnection:
        """Get or create a connection for the specified protocol."""
        if protocol not in self._connections:
            port = self.get_port(protocol)

            if protocol == Protocol.MODBUS_TCP:
                self._connections[protocol] = ModbusTCPConnection(
                    self.host, port, self.timeout
                )
            elif protocol == Protocol.HTTP:
                self._connections[protocol] = HTTPConnection(
                    self.host, port, self.timeout, use_ssl=False
                )
            elif protocol == Protocol.HTTPS:
                self._connections[protocol] = HTTPConnection(
                    self.host, port, self.timeout, use_ssl=True
                )
            elif protocol == Protocol.SNMP:
                self._connections[protocol] = SNMPConnection(
                    self.host, port, self.timeout
                )
            elif protocol == Protocol.VNC:
                self._connections[protocol] = VNCConnection(
                    self.host, port, self.timeout
                )
            elif protocol == Protocol.TELNET:
                self._connections[protocol] = TelnetConnection(
                    self.host, port, self.timeout
                )
            elif protocol == Protocol.SSH:
                self._connections[protocol] = SSHConnection(
                    self.host, port, self.timeout
                )

        return self._connections[protocol]

    def test_connectivity(self, protocol: Protocol) -> ConnectionResult:
        """Test connectivity using specified protocol."""
        connection = self.get_connection(protocol)
        return connection.connect()

    def test_all_protocols(self) -> Dict[Protocol, ConnectionResult]:
        """Test connectivity using all supported protocols."""
        results = {}
        for protocol in Protocol:
            results[protocol] = self.test_connectivity(protocol)
        return results

    def close_all(self) -> None:
        """Close all open connections."""
        for connection in self._connections.values():
            connection.disconnect()
        self._connections.clear()

    @contextmanager
    def connection(self, protocol: Protocol) -> Generator[BaseConnection, None, None]:
        """Context manager for connections."""
        conn = self.get_connection(protocol)
        try:
            conn.connect()
            yield conn
        finally:
            conn.disconnect()
