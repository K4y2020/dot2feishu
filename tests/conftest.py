"""Every test is offline; Starlette's in-process TestClient needs no sockets."""

import socket

import pytest


@pytest.fixture(autouse=True)
def deny_live_network(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("Offline tests cannot use live DNS or network connections")

    monkeypatch.setattr(socket, "getaddrinfo", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
    monkeypatch.setattr(socket.socket, "bind", denied)
    monkeypatch.setattr(socket.socket, "listen", denied)
