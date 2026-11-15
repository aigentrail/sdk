from __future__ import annotations

import http.client
import json
import math
import socket
import threading
import time
import urllib.request
from contextlib import suppress
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit

PROTOCOL = "operation_v1"
BODY_SIZE_MAX = 65536
DEADLINE_SECONDS = 9.0


class QuotaExhaustedError(ValueError):
    pass


class AttemptClosedError(ValueError):
    pass


class ConsumptionUncertainError(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl) -> None:
        return None


def same_origin_link(endpoint: str, link: str) -> str:
    base = urlsplit(endpoint)
    if base.scheme not in ("http", "https") or not base.netloc:
        raise ValueError("invalid decision endpoint")
    if base.username is not None or base.query or base.fragment:
        raise ValueError("invalid decision endpoint")
    if not isinstance(link, str) or not link:
        raise ValueError("missing admission control")
    target = urlsplit(urljoin(endpoint, link))
    if (target.scheme, target.netloc) != (base.scheme, base.netloc):
        raise ValueError("admission control leaves decision origin")
    if target.username is not None or target.fragment:
        raise ValueError("invalid admission control")
    return target.geturl()


class AdmissionClient:
    def __init__(
        self,
        endpoint: str,
        api_key: str,
        timeout: float,
        *,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.endpoint = endpoint
        self.api_key = api_key
        self.timeout = timeout
        self.clock = clock
        self.monotonic = monotonic

    def authorize(self, request_id: str, link: Any) -> None:
        if not isinstance(link, dict) or not request_id:
            raise ValueError("invalid admission resource")
        if link.get("required") is not True or link.get("protocol") != PROTOCOL:
            raise ValueError("unsupported admission protocol")
        digest = link.get("proposal_hash")
        if not isinstance(digest, str) or len(digest) != 64:
            raise ValueError("invalid proposal hash")
        if len(bytes.fromhex(digest)) != 32:
            raise ValueError("invalid proposal hash")
        deadline = self.monotonic() + DEADLINE_SECONDS
        target = urlsplit(same_origin_link(self.endpoint, link.get("reserve_url")))
        connection_type = (
            http.client.HTTPSConnection
            if target.scheme == "https"
            else http.client.HTTPConnection
        )
        connection = connection_type(
            target.hostname, target.port, timeout=min(self.timeout, 3.0)
        )
        try:
            reserved = self.exchange(
                connection, link.get("reserve_url"), digest, deadline
            )
            if reserved.get("outcome") == "quota_exhausted":
                raise QuotaExhaustedError("tool-call allowance exhausted")
            if (
                reserved.get("outcome") == "verified"
                and reserved.get("execution_authorized") is False
            ):
                reservation = reserved.get("reservation")
                if isinstance(reservation, dict) and reservation.get("state") in (
                    "consumed",
                    "released",
                ):
                    self.checked_receipt(reserved, request_id, reservation["state"])
                    raise AttemptClosedError("attempt already consumed or canceled")
            expected = self.checked_receipt(reserved, request_id, "reserved")
            if reserved.get("execution_authorized") is not False:
                raise ValueError("reservation cannot authorize execution")
            try:
                consumed = self.exchange(
                    connection, reserved.get("consume_url"), digest, deadline
                )
                actual = self.checked_receipt(consumed, request_id, "consumed")
                same_reservation = (
                    actual["request_id"] == expected["request_id"]
                    and actual["policy_digest"] == expected["policy_digest"]
                    and actual["expires_at"] <= expected["expires_at"]
                )
                if same_reservation and consumed.get("execution_authorized") is False:
                    raise AttemptClosedError("attempt already consumed or canceled")
                if (
                    not same_reservation
                    or consumed.get("execution_authorized") is not True
                ):
                    raise ValueError("execution was not authorized")
                if self.monotonic() >= deadline:
                    raise TimeoutError("admission deadline exceeded")
            except AttemptClosedError:
                raise
            except Exception as error:
                raise ConsumptionUncertainError(
                    "consumption could not be confirmed"
                ) from error
        finally:
            connection.close()

    def checked_receipt(self, receipt: dict, request_id: str, state: str) -> dict:
        reservation = receipt.get("reservation")
        if receipt.get("outcome") != "verified" or not isinstance(reservation, dict):
            raise ValueError("unverified admission receipt")
        if (
            reservation.get("request_id") != request_id
            or reservation.get("state") != state
        ):
            raise ValueError("admission identity mismatch")
        policy_digest = reservation.get("policy_digest")
        if not isinstance(policy_digest, str) or len(policy_digest) != 64:
            raise ValueError("invalid admission policy digest")
        if len(bytes.fromhex(policy_digest)) != 32:
            raise ValueError("invalid admission policy digest")
        expiry = reservation.get("expires_at")
        if type(expiry) is not int:
            raise ValueError("invalid admission expiry")
        now = math.floor(self.clock())
        if not 0 < now < expiry or expiry - now > 30:
            raise ValueError("expired or invalid admission lease")
        return {
            key: reservation[key]
            for key in ("request_id", "state", "policy_digest", "expires_at")
        }

    def exchange(
        self,
        connection: http.client.HTTPConnection,
        link: str,
        digest: str,
        deadline: float,
    ) -> dict:
        target = same_origin_link(self.endpoint, link)
        remaining = deadline - self.monotonic()
        if remaining <= 0:
            raise TimeoutError("admission deadline exceeded")
        parsed = urlsplit(target)
        timer = None
        try:
            connection.timeout = min(self.timeout, 3.0, remaining)
            if connection.sock is None:
                connection.connect()
            connection.sock.settimeout(connection.timeout)
            remaining = deadline - self.monotonic()
            if remaining <= 0:
                raise TimeoutError("admission deadline exceeded")
            transport = connection.sock
            timer = threading.Timer(remaining, interrupt_transport, (transport,))
            timer.daemon = True
            timer.start()
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            connection.request(
                "POST",
                path,
                body=json.dumps({"proposal_hash": digest}).encode(),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.api_key}",
                    "User-Agent": "gentrail-sdk-python",
                },
            )
            with connection.getresponse() as response:
                if response.status != 200:
                    raise ValueError("admission request failed")
                raw = response.read(BODY_SIZE_MAX + 1)
                if len(raw) > BODY_SIZE_MAX:
                    raise ValueError("admission response too large")
                receipt = json.loads(raw)
            if not isinstance(receipt, dict):
                raise ValueError("invalid admission response")
            return receipt
        finally:
            if timer is not None:
                timer.cancel()


def interrupt_transport(transport: socket.socket) -> None:
    with suppress(OSError):
        transport.shutdown(socket.SHUT_RDWR)
