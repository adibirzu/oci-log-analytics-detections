"""Deny network sockets for the credential-free release subprocess harness.

This module is loaded only when ``release_checklist`` sets ``PYTHONPATH`` to
the scripts directory.  It deliberately records attempted connections in the
path supplied by ``OFFLINE_EGRESS_RECEIPT`` so a network-denial failure is
structured evidence, not an assertion based on command text.
"""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path


_RECEIPT = os.environ.get("OFFLINE_EGRESS_RECEIPT")


def _record(kind: str, address: object) -> None:
    if not _RECEIPT:
        return
    payload = {"attempted": True, "kind": kind, "address": repr(address)}
    try:
        Path(_RECEIPT).write_text(json.dumps(payload) + "\n", encoding="utf-8")
    except OSError:
        pass


class _DeniedSocket(socket.socket):
    def connect(self, address):  # type: ignore[no-untyped-def]
        _record("connect", address)
        raise RuntimeError("offline release stage denied network socket")

    def connect_ex(self, address):  # type: ignore[no-untyped-def]
        _record("connect_ex", address)
        raise OSError("offline release stage denied network socket")


socket.socket = _DeniedSocket  # type: ignore[assignment]


def _denied_create_connection(address, *args, **kwargs):  # type: ignore[no-untyped-def]
    _record("create_connection", address)
    raise OSError("offline release stage denied network socket")


socket.create_connection = _denied_create_connection  # type: ignore[assignment]
