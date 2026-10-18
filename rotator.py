"""Core logic for AETHER: talk to Tor's control port and verify the exit IP.

This module has no UI code, so it can be imported and used from other scripts:

    from rotator import TorRotator

    rotator = TorRotator()          # auto-discovers local Tor ports
    result = rotator.rotate_ip()
    print(result.previous.ip, "->", result.current.ip)
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Sequence, Tuple

import requests
import stem
from requests.exceptions import RequestException
from stem import Signal
from stem.connection import AuthenticationFailure
from stem.control import Controller

__version__ = "1.1.0"

LOCALHOST = "127.0.0.1"

# (control_port, socks_port) pairs, in the order they are tried.
#   Tor Browser (Windows/macOS/Linux bundle): 9151 / 9150
#   Tor system service (Linux/Kali):          9051 / 9050
TOR_PORT_PAIRS: Tuple[Tuple[int, int], ...] = ((9151, 9150), (9051, 9050))

# Tor rate-limits NEWNYM; requests sent sooner than this are delayed by Tor.
NEWNYM_MIN_INTERVAL = 10.0


@dataclass(frozen=True)
class IpCheckEndpoint:
    """A JSON endpoint that reports the caller's IP address.

    ``tor_key`` is the JSON field that says whether the request came through
    Tor; endpoints without one leave that fact unknown.
    """

    url: str
    ip_key: str
    tor_key: Optional[str] = None


# Tried in order; the first one that answers wins. The Tor Project's endpoint
# comes first because it also confirms the traffic really exits through Tor.
# The others are fallbacks for when it is unreachable from a given exit.
DEFAULT_ENDPOINTS: Tuple[IpCheckEndpoint, ...] = (
    IpCheckEndpoint("https://check.torproject.org/api/ip", "IP", "IsTor"),
    IpCheckEndpoint("https://api.ipify.org?format=json", "ip"),
    IpCheckEndpoint("https://httpbin.org/ip", "origin"),
)


class TorError(Exception):
    """Base class for all errors raised by this module."""


class TorConnectionError(TorError):
    """Tor (control port or SOCKS proxy) could not be reached."""


class TorAuthError(TorError):
    """Authentication against the Tor control port failed."""


@dataclass(frozen=True)
class ExitInfo:
    """What the outside world sees when we connect through Tor.

    ``is_tor`` is None when the endpoint that answered cannot tell.
    """

    ip: str
    is_tor: Optional[bool] = None


@dataclass(frozen=True)
class RotationResult:
    """Outcome of one call to :meth:`TorRotator.rotate_ip`."""

    previous: ExitInfo
    current: ExitInfo
    attempts: int

    @property
    def changed(self) -> bool:
        return self.previous.ip != self.current.ip


def port_is_open(port: int, host: str = LOCALHOST, timeout: float = 1.0) -> bool:
    """Return True if something is accepting TCP connections on host:port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def find_tor_ports(host: str = LOCALHOST) -> Optional[Tuple[int, int]]:
    """Find a (control_port, socks_port) pair where both ports are open.

    Pairs are tried together so a Tor Browser control port is never combined
    with a system-service SOCKS port (or vice versa).
    """
    for control_port, socks_port in TOR_PORT_PAIRS:
        if port_is_open(control_port, host) and port_is_open(socks_port, host):
            return control_port, socks_port
    return None


class TorRotator:
    """Request new Tor identities and verify the resulting exit IP."""

    def __init__(
        self,
        control_port: Optional[int] = None,
        socks_port: Optional[int] = None,
        password: Optional[str] = None,
        host: str = LOCALHOST,
        endpoints: Sequence[IpCheckEndpoint] = DEFAULT_ENDPOINTS,
        timeout: float = 15.0,
        retries: int = 1,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if control_port is None or socks_port is None:
            pair = find_tor_ports(host)
            if pair is None:
                raise TorConnectionError(
                    "Tor ports not found. Start Tor Browser (ports 9151/9150) "
                    "or the Tor service (ports 9051/9050), or pass the ports "
                    "explicitly."
                )
            control_port = control_port if control_port is not None else pair[0]
            socks_port = socks_port if socks_port is not None else pair[1]

        self.host = host
        self.control_port = control_port
        self.socks_port = socks_port
        self.password = password
        self.endpoints = tuple(endpoints)
        self.timeout = timeout
        self.retries = retries
        self._sleep = sleep
        self._clock = clock
        self._last_newnym: Optional[float] = None

        # socks5h = DNS is resolved by Tor, not by the local resolver.
        proxy = f"socks5h://{host}:{socks_port}"
        self.proxies: Dict[str, str] = {"http": proxy, "https": proxy}

    def _query(self, endpoint: IpCheckEndpoint) -> ExitInfo:
        """Ask one endpoint which IP we appear as (raises on any failure).

        A throw-away session with ``Connection: close`` is used so a pooled
        keep-alive socket can never hide the effect of a rotation.
        """
        with requests.Session() as session:
            session.proxies.update(self.proxies)
            response = session.get(
                endpoint.url,
                timeout=self.timeout,
                headers={"Connection": "close"},
            )
            response.raise_for_status()
            data = response.json()
        # Some endpoints return a comma-separated list; the first entry is ours.
        ip = str(data[endpoint.ip_key]).split(",")[0].strip()
        if not ip:
            raise ValueError("empty IP in response")
        is_tor = None
        if endpoint.tor_key is not None and endpoint.tor_key in data:
            is_tor = bool(data[endpoint.tor_key])
        return ExitInfo(ip=ip, is_tor=is_tor)

    def get_exit_info(self) -> ExitInfo:
        """Find out which IP the outside world sees for traffic via Tor.

        Endpoints are tried in order (each up to ``retries`` extra times); the
        first answer wins. If only a fallback answers, ``is_tor`` is None
        because that endpoint cannot confirm Tor usage.
        """
        failures = []
        for endpoint in self.endpoints:
            for _ in range(1 + max(0, self.retries)):
                try:
                    return self._query(endpoint)
                except (RequestException, ValueError, KeyError, TypeError) as exc:
                    reason = f"{type(exc).__name__}: {str(exc)[:120]}"
            failures.append(f"  - {endpoint.url} -> {reason}")
        raise TorConnectionError(
            f"No IP-check endpoint answered through the Tor SOCKS proxy on port "
            f"{self.socks_port}. Tor may still be bootstrapping, or the exit "
            f"blocks these sites; try again in a moment.\n" + "\n".join(failures)
        )

    def _wait_for_newnym_slot(self) -> None:
        """Sleep until Tor will accept another NEWNYM without delaying it."""
        if self._last_newnym is None:
            return
        remaining = NEWNYM_MIN_INTERVAL - (self._clock() - self._last_newnym)
        if remaining > 0:
            self._sleep(remaining)

    def _signal_newnym(self) -> None:
        """Send NEWNYM over the control port."""
        self._wait_for_newnym_slot()
        try:
            with Controller.from_port(address=self.host, port=self.control_port) as controller:
                controller.authenticate(password=self.password)
                controller.signal(Signal.NEWNYM)
        except AuthenticationFailure as exc:
            raise TorAuthError(
                f"Authentication on control port {self.control_port} failed: {exc}. "
                "Use a password (--ask-password / TOR_CONTROL_PASSWORD), or enable "
                "cookie authentication and make sure your user can read the cookie "
                "file (on Debian/Kali: add yourself to the 'debian-tor' group)."
            ) from exc
        except (stem.SocketError, OSError) as exc:
            raise TorConnectionError(
                f"Could not connect to the control port {self.control_port}: {exc}"
            ) from exc
        except stem.ControllerError as exc:
            raise TorError(f"Tor rejected the NEWNYM signal: {exc}") from exc
        self._last_newnym = self._clock()

    def rotate_ip(
        self,
        max_attempts: int = 3,
        previous: Optional[ExitInfo] = None,
    ) -> RotationResult:
        """Request a new identity and report whether the exit IP changed.

        Tor may legitimately pick the same exit again, so up to
        ``max_attempts`` NEWNYM signals are sent. If the IP is still the same
        afterwards, ``result.changed`` is False (this is not an error).

        Pass ``previous`` (an :class:`ExitInfo` you already have) to save one
        request to the check endpoint.
        """
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")

        if previous is None:
            previous = self.get_exit_info()

        current = previous
        for attempt in range(1, max_attempts + 1):
            self._signal_newnym()
            current = self.get_exit_info()
            if current.ip != previous.ip:
                return RotationResult(previous, current, attempt)
        return RotationResult(previous, current, max_attempts)
