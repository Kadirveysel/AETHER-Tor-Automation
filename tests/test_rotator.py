"""Unit tests for rotator.py. No real Tor instance or network is needed."""

import pytest
import stem
from stem.connection import IncorrectPassword

import rotator
from rotator import (
    ExitInfo,
    TorAuthError,
    TorConnectionError,
    TorRotator,
    find_tor_ports,
)


class FakeClock:
    """Deterministic clock whose sleep() advances time instead of waiting."""

    def __init__(self):
        self.now = 1000.0
        self.slept = []

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


class FakeController:
    """Stands in for stem.control.Controller; records NEWNYM signals."""

    signals = []
    auth_error = None
    socket_error = None

    @classmethod
    def from_port(cls, address, port):
        if cls.socket_error is not None:
            raise cls.socket_error
        return cls()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def authenticate(self, password=None):
        if self.auth_error is not None:
            raise self.auth_error

    def signal(self, signal):
        type(self).signals.append(signal)


@pytest.fixture(autouse=True)
def reset_controller(monkeypatch):
    FakeController.signals = []
    FakeController.auth_error = None
    FakeController.socket_error = None
    monkeypatch.setattr(rotator, "Controller", FakeController)


def make_rotator(exits, fake=None):
    """Build a rotator whose get_exit_info() yields the given IPs in order."""
    fake = fake or FakeClock()
    instance = TorRotator(
        control_port=9051, socks_port=9050, sleep=fake.sleep, clock=fake.clock
    )
    queue = iter(exits)
    instance.get_exit_info = lambda: ExitInfo(ip=next(queue), is_tor=True)
    return instance, fake


# --- port discovery ---------------------------------------------------------

def test_find_tor_ports_prefers_tor_browser_pair(monkeypatch):
    monkeypatch.setattr(rotator, "port_is_open", lambda port, host="127.0.0.1", timeout=1.0: True)
    assert find_tor_ports() == (9151, 9150)


def test_find_tor_ports_never_mixes_pairs(monkeypatch):
    # Tor Browser control port is open but its SOCKS port is not; the service
    # pair is fully open. The mixed (9151, 9050) combination must not be used.
    open_ports = {9151, 9051, 9050}
    monkeypatch.setattr(
        rotator, "port_is_open", lambda port, host="127.0.0.1", timeout=1.0: port in open_ports
    )
    assert find_tor_ports() == (9051, 9050)


def test_find_tor_ports_returns_none_when_nothing_listens(monkeypatch):
    monkeypatch.setattr(rotator, "port_is_open", lambda port, host="127.0.0.1", timeout=1.0: False)
    assert find_tor_ports() is None


def test_init_raises_when_tor_not_found(monkeypatch):
    monkeypatch.setattr(rotator, "find_tor_ports", lambda host="127.0.0.1": None)
    with pytest.raises(TorConnectionError):
        TorRotator()


def test_explicit_ports_skip_discovery(monkeypatch):
    def boom(host="127.0.0.1"):
        raise AssertionError("discovery should not run")

    monkeypatch.setattr(rotator, "find_tor_ports", boom)
    instance = TorRotator(control_port=1234, socks_port=5678)
    assert instance.proxies["https"] == "socks5h://127.0.0.1:5678"


# --- exit info --------------------------------------------------------------

class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class FakeSession:
    payload = {"IsTor": True, "IP": "203.0.113.7"}
    seen_headers = None

    def __init__(self):
        self.proxies = {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get(self, url, timeout, headers):
        type(self).seen_headers = headers
        return FakeResponse(type(self).payload)


def test_get_exit_info_parses_tor_project_response(monkeypatch):
    monkeypatch.setattr(rotator.requests, "Session", FakeSession)
    instance = TorRotator(control_port=9051, socks_port=9050)
    info = instance.get_exit_info()
    assert info == ExitInfo(ip="203.0.113.7", is_tor=True)
    assert FakeSession.seen_headers == {"Connection": "close"}


def test_get_exit_info_wraps_bad_payload(monkeypatch):
    monkeypatch.setattr(FakeSession, "payload", {"unexpected": "shape"})
    monkeypatch.setattr(rotator.requests, "Session", FakeSession)
    instance = TorRotator(control_port=9051, socks_port=9050)
    with pytest.raises(TorConnectionError):
        instance.get_exit_info()


# --- rotation ---------------------------------------------------------------

def test_rotate_reports_change_on_first_attempt():
    instance, _ = make_rotator(["1.1.1.1", "2.2.2.2"])
    result = instance.rotate_ip()
    assert result.changed
    assert result.attempts == 1
    assert (result.previous.ip, result.current.ip) == ("1.1.1.1", "2.2.2.2")
    assert len(FakeController.signals) == 1


def test_rotate_retries_when_exit_is_unchanged():
    instance, _ = make_rotator(["1.1.1.1", "1.1.1.1", "2.2.2.2"])
    result = instance.rotate_ip(max_attempts=3)
    assert result.changed
    assert result.attempts == 2
    assert len(FakeController.signals) == 2


def test_rotate_gives_up_without_error_when_ip_never_changes():
    instance, _ = make_rotator(["1.1.1.1", "1.1.1.1", "1.1.1.1"])
    result = instance.rotate_ip(max_attempts=2)
    assert not result.changed
    assert result.attempts == 2


def test_rotate_uses_supplied_previous_exit():
    instance, _ = make_rotator(["2.2.2.2"])  # only one lookup is allowed
    result = instance.rotate_ip(previous=ExitInfo("1.1.1.1", True))
    assert result.changed


def test_rotate_rejects_invalid_attempts():
    instance, _ = make_rotator([])
    with pytest.raises(ValueError):
        instance.rotate_ip(max_attempts=0)


def test_consecutive_newnym_respects_tor_rate_limit():
    # Each rotate_ip() without `previous` does two lookups (before and after).
    instance, fake = make_rotator(["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"])
    instance.rotate_ip()
    instance.rotate_ip()
    # First signal needs no wait; the second must wait out the 10s interval.
    assert fake.slept == [pytest.approx(rotator.NEWNYM_MIN_INTERVAL)]


# --- error mapping ----------------------------------------------------------

def test_authentication_failure_becomes_tor_auth_error():
    FakeController.auth_error = IncorrectPassword("bad password")
    instance, _ = make_rotator(["1.1.1.1"])
    with pytest.raises(TorAuthError):
        instance.rotate_ip()


def test_unreachable_control_port_becomes_connection_error():
    FakeController.socket_error = stem.SocketError("refused")
    instance, _ = make_rotator(["1.1.1.1"])
    with pytest.raises(TorConnectionError):
        instance.rotate_ip()
