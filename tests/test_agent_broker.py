from __future__ import annotations

import os
import socket
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from echo_veil import agent_cli
from echo_veil.agent_broker import (
    BROKER_TELEMETRY_SCHEMA,
    BrokerClient,
    BrokerError,
    BrokerServer,
    broker_authority_id,
)


def _ready_doctor() -> dict[str, Any]:
    return {
        "adapter_ready": True,
        "local_protection_ready": True,
        "profile": "echo-universal-qwen3-v1",
        "protection_policy": "required",
        "security_schema": "scoped-v2",
        "scope_bound": True,
        "writer_serialization": "profile-sqlite-lease",
        "plaintext_fallback_attempts": 0,
        "reconciliation_backlog": 0,
        "quarantined_records": 0,
        "readiness": {
            "healthy": True,
            "retrieval_wired": True,
            "persistence_wired": True,
            "restart_restored": True,
            "layer_contract_wired": True,
            "context_trace_wired": True,
            "competing_memory_wired": True,
            "content_policy_wired": True,
        },
        "memory_layers": {"all_records_shielded": True},
        "retrieval": {
            "unindexed_payload_count": 0,
            "answerability_gate": "semantic-predicate-v1",
        },
        "embedding": {
            "backend": "ollama",
            "model": "qwen3-embedding:latest",
            "dimension": 1024,
            "semantic": True,
        },
    }


@pytest.fixture
def broker_root() -> Any:
    # Darwin's AF_UNIX path is short; pytest's descriptive temp hierarchy is
    # intentionally much longer than a real profile path. Linux runners do not
    # necessarily expose Darwin's /private/tmp alias.
    private_tmp = Path("/private/tmp")
    if not private_tmp.is_dir():
        private_tmp = Path(tempfile.gettempdir())
    with tempfile.TemporaryDirectory(prefix="evb-", dir=private_tmp) as directory:
        root = Path(directory).resolve(strict=True)
        root.chmod(0o700)
        yield root


def _start_server(
    socket_path: Path,
    dispatcher: Any,
) -> tuple[threading.Event, threading.Thread]:
    stop = threading.Event()
    ready = threading.Event()
    server = BrokerServer(socket_path, dispatcher)
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"stop_event": stop, "ready_event": ready},
        daemon=True,
    )
    thread.start()
    assert ready.wait(2.0)
    return stop, thread


def _stop_server(stop: threading.Event, thread: threading.Thread) -> None:
    stop.set()
    thread.join(2.0)
    assert not thread.is_alive()


def _start_configured_server(
    server: BrokerServer,
) -> tuple[threading.Event, threading.Thread]:
    stop = threading.Event()
    ready = threading.Event()
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"stop_event": stop, "ready_event": ready},
        daemon=True,
    )
    thread.start()
    assert ready.wait(2.0)
    return stop, thread


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="Unix socket required")
def test_broker_startup_failure_preserves_active_server(broker_root: Path) -> None:
    socket_path = broker_root / "echo.sock"
    stop, thread = _start_server(socket_path, lambda *_args: {"value": 7})
    identity = socket_path.stat().st_ino
    try:
        second = BrokerServer(socket_path, lambda *_args: {"value": 8})
        with pytest.raises(BrokerError, match="already active"):
            second.serve_forever()
        assert socket_path.stat().st_ino == identity
        assert BrokerClient(socket_path, caller="pi").call("doctor", {})["value"] == 7
    finally:
        _stop_server(stop, thread)


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="Unix socket required")
def test_broker_probe_timeout_does_not_unlink_endpoint(
    broker_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    socket_path = broker_root / "echo.sock"
    stop, thread = _start_server(socket_path, lambda *_args: {"value": 7})
    identity = socket_path.stat().st_ino
    try:
        second = BrokerServer(socket_path, lambda *_args: {"value": 8})

        def congested_connect(_socket: socket.socket, _address: object) -> None:
            raise TimeoutError("listener backlog is congested")

        with monkeypatch.context() as patch:
            patch.setattr(socket.socket, "connect", congested_connect)
            with pytest.raises(BrokerError, match="cannot be verified"):
                second._remove_stale_socket()
        assert socket_path.stat().st_ino == identity
        assert BrokerClient(socket_path, caller="pi").call("doctor", {})["value"] == 7
    finally:
        _stop_server(stop, thread)


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="Unix socket required")
def test_broker_reclaims_a_confirmed_stale_socket(broker_root: Path) -> None:
    socket_path = broker_root / "echo.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stale:
        stale.bind(os.fspath(socket_path))
        socket_path.chmod(0o600)
    stop, thread = _start_server(socket_path, lambda *_args: {"value": 7})
    try:
        assert BrokerClient(socket_path, caller="pi").call("doctor", {})["value"] == 7
    finally:
        _stop_server(stop, thread)


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="Unix socket required")
@pytest.mark.parametrize("stage", ("writer", "connection"))
def test_broker_thread_start_failure_cleans_up_without_masking_error(
    broker_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    socket_path = broker_root / "echo.sock"
    server = BrokerServer(socket_path, lambda *_args: {})
    start = threading.Thread.start

    def fail_start(thread: threading.Thread) -> None:
        if thread.name == f"echo-veil-broker-{stage}":
            raise RuntimeError("cannot start test worker")
        start(thread)

    monkeypatch.setattr(threading.Thread, "start", fail_start)
    connection, peer = socket.socketpair()
    with connection, peer:
        monkeypatch.setattr(socket.socket, "accept", lambda _sock: (connection, ""))
        with pytest.raises(RuntimeError, match="cannot start test worker"):
            server.serve_forever()
        assert not socket_path.exists()
        if stage == "connection":
            assert connection.fileno() == -1


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="Unix socket required")
def test_owner_only_broker_round_trip_is_bound_and_payload_free(
    broker_root: Path,
) -> None:
    socket_path = broker_root / "echo.sock"
    observed: list[tuple[str, dict[str, Any], str]] = []

    def dispatch(action: str, arguments: Any, caller: str) -> dict[str, Any]:
        observed.append((action, dict(arguments), caller))
        return {"value": 7}

    stop, thread = _start_server(socket_path, dispatch)
    try:
        result = BrokerClient(socket_path, caller="pi").call(
            "doctor",
            {"bounded": True},
        )
    finally:
        _stop_server(stop, thread)

    assert observed == [("doctor", {"bounded": True}, "pi")]
    assert result["value"] == 7
    telemetry = result["broker_transport"]
    assert telemetry["schema"] == BROKER_TELEMETRY_SCHEMA
    assert telemetry["payload_included"] is False
    assert telemetry["dispatch_ms"] >= 0.0
    assert telemetry["round_trip_ms"] >= telemetry["dispatch_ms"]
    assert not socket_path.exists()
    authority = broker_authority_id(socket_path)
    assert authority.startswith("sha256:")
    assert str(broker_root) not in authority


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="Unix socket required")
def test_broker_serializes_concurrent_callers(broker_root: Path) -> None:
    socket_path = broker_root / "echo.sock"
    state_lock = threading.Lock()
    active = 0
    maximum_active = 0

    def dispatch(action: str, arguments: Any, caller: str) -> dict[str, Any]:
        nonlocal active, maximum_active
        del action, arguments, caller
        with state_lock:
            active += 1
            maximum_active = max(maximum_active, active)
        time.sleep(0.02)
        with state_lock:
            active -= 1
        return {"ok": True}

    stop, server_thread = _start_server(socket_path, dispatch)
    results: list[dict[str, Any]] = []
    result_lock = threading.Lock()

    def invoke(caller: str) -> None:
        value = BrokerClient(socket_path, caller=caller).call("doctor", {})
        with result_lock:
            results.append(value)

    callers = ["pi", "codex", "pi", "codex"]
    threads = [threading.Thread(target=invoke, args=(caller,)) for caller in callers]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(2.0)
            assert not thread.is_alive()
    finally:
        _stop_server(stop, server_thread)

    assert len(results) == len(callers)
    assert maximum_active == 1


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="Unix socket required")
def test_broker_rejects_saturation_before_third_dispatch(
    broker_root: Path,
) -> None:
    socket_path = broker_root / "echo.sock"
    entered = threading.Event()
    release = threading.Event()
    dispatched: list[str] = []

    def dispatch(_action: str, arguments: Any, _caller: str) -> dict[str, Any]:
        marker = str(arguments["marker"])
        dispatched.append(marker)
        if marker == "first":
            entered.set()
            assert release.wait(2.0)
        return {"marker": marker}

    server = BrokerServer(
        socket_path,
        dispatch,
        queue_depth=1,
        per_caller_quota=1,
    )
    stop, server_thread = _start_configured_server(server)
    results: list[str] = []

    def invoke(marker: str) -> None:
        response = BrokerClient(socket_path, caller="pi").call(
            "doctor",
            {"marker": marker},
        )
        results.append(str(response["marker"]))

    first = threading.Thread(target=invoke, args=("first",))
    second = threading.Thread(target=invoke, args=("second",))
    try:
        first.start()
        assert entered.wait(1.0)
        second.start()
        deadline = time.monotonic() + 1.0
        while server.metrics()["queued"] != 1 and time.monotonic() < deadline:
            time.sleep(0.005)
        assert server.metrics()["queued"] == 1
        with pytest.raises(BrokerError, match="saturated"):
            BrokerClient(socket_path, caller="pi").call(
                "doctor",
                {"marker": "third"},
            )
        assert "third" not in dispatched
        release.set()
        first.join(2.0)
        second.join(2.0)
        assert not first.is_alive()
        assert not second.is_alive()
    finally:
        release.set()
        _stop_server(stop, server_thread)

    assert dispatched == ["first", "second"]
    assert sorted(results) == ["first", "second"]
    metrics = server.metrics()
    assert metrics["rejected"] >= 1
    assert metrics["payload_included"] is False


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="Unix socket required")
def test_broker_queue_is_fair_across_callers(broker_root: Path) -> None:
    socket_path = broker_root / "echo.sock"
    entered = threading.Event()
    release = threading.Event()
    order: list[str] = []

    def dispatch(_action: str, arguments: Any, _caller: str) -> dict[str, Any]:
        marker = str(arguments["marker"])
        order.append(marker)
        if marker == "a1":
            entered.set()
            assert release.wait(2.0)
        return {"marker": marker}

    server = BrokerServer(
        socket_path,
        dispatch,
        queue_depth=4,
        per_caller_quota=3,
    )
    stop, server_thread = _start_configured_server(server)

    def invoke(caller: str, marker: str) -> None:
        BrokerClient(socket_path, caller=caller).call(
            "doctor",
            {"marker": marker},
        )

    threads = [
        threading.Thread(target=invoke, args=("pi", "a1")),
        threading.Thread(target=invoke, args=("pi", "a2")),
        threading.Thread(target=invoke, args=("pi", "a3")),
        threading.Thread(target=invoke, args=("codex", "b1")),
    ]
    try:
        threads[0].start()
        assert entered.wait(1.0)
        for thread in threads[1:]:
            thread.start()
            time.sleep(0.01)
        deadline = time.monotonic() + 1.0
        while server.metrics()["queued"] != 3 and time.monotonic() < deadline:
            time.sleep(0.005)
        assert server.metrics()["queued"] == 3
        release.set()
        for thread in threads:
            thread.join(2.0)
            assert not thread.is_alive()
    finally:
        release.set()
        _stop_server(stop, server_thread)

    assert order == ["a1", "a2", "b1", "a3"]
    assert server.metrics()["queue_wait_p95_ms"] >= 0.0


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="Unix socket required")
def test_broker_cancels_only_a_queued_deadline(broker_root: Path) -> None:
    socket_path = broker_root / "echo.sock"
    entered = threading.Event()
    release = threading.Event()
    dispatched: list[str] = []

    def dispatch(_action: str, arguments: Any, _caller: str) -> dict[str, Any]:
        marker = str(arguments["marker"])
        dispatched.append(marker)
        if marker == "active":
            entered.set()
            assert release.wait(2.0)
        return {"marker": marker}

    server = BrokerServer(
        socket_path,
        dispatch,
        queue_depth=1,
        per_caller_quota=1,
        request_deadline_seconds=0.1,
    )
    stop, server_thread = _start_configured_server(server)
    active_result: list[str] = []

    def invoke_active() -> None:
        result = BrokerClient(socket_path, caller="pi", timeout_seconds=2.0).call(
            "doctor",
            {"marker": "active"},
        )
        active_result.append(str(result["marker"]))

    active = threading.Thread(target=invoke_active)
    try:
        active.start()
        assert entered.wait(1.0)
        with pytest.raises(BrokerError, match="deadline"):
            BrokerClient(
                socket_path,
                caller="codex",
                timeout_seconds=2.0,
            ).call("doctor", {"marker": "queued"})
        assert server.metrics()["queued"] == 0
        assert "queued" not in dispatched
        release.set()
        active.join(2.0)
        assert not active.is_alive()
    finally:
        release.set()
        _stop_server(stop, server_thread)

    assert active_result == ["active"]
    assert dispatched == ["active"]
    assert server.metrics()["deadline_rejected"] == 1


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="Unix socket required")
def test_broker_active_dispatch_returns_definite_result_after_queue_deadline(
    broker_root: Path,
) -> None:
    socket_path = broker_root / "echo.sock"
    entered = threading.Event()
    release = threading.Event()

    def dispatch(_action: str, _arguments: Any, _caller: str) -> dict[str, Any]:
        entered.set()
        assert release.wait(2.0)
        return {"committed": True}

    server = BrokerServer(
        socket_path,
        dispatch,
        queue_depth=1,
        per_caller_quota=1,
        request_deadline_seconds=0.1,
    )
    stop, server_thread = _start_configured_server(server)
    responses: list[dict[str, Any]] = []

    def invoke() -> None:
        responses.append(
            BrokerClient(
                socket_path,
                caller="pi",
                timeout_seconds=2.0,
            ).call("remember", {})
        )

    thread = threading.Thread(target=invoke)
    try:
        thread.start()
        assert entered.wait(1.0)
        time.sleep(0.15)
        release.set()
        thread.join(2.0)
        assert not thread.is_alive()
    finally:
        release.set()
        _stop_server(stop, server_thread)

    assert len(responses) == 1
    assert responses[0]["committed"] is True
    assert responses[0]["broker_transport"]["schema"] == ("echo-veil-broker-latency-v1")
    assert server.metrics()["deadline_rejected"] == 0


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="Unix socket required")
def test_broker_errors_are_generic_and_socket_permissions_are_enforced(
    broker_root: Path,
) -> None:
    root = broker_root
    socket_path = root / "echo.sock"

    def fail(action: str, arguments: Any, caller: str) -> dict[str, Any]:
        del action, arguments, caller
        raise RuntimeError("private profile path and secret")

    stop, thread = _start_server(socket_path, fail)
    try:
        with pytest.raises(BrokerError, match="request failed") as captured:
            BrokerClient(socket_path, caller="codex").call("doctor", {})
        assert "private" not in str(captured.value)
        assert "secret" not in str(captured.value)
    finally:
        _stop_server(stop, thread)

    root.chmod(0o755)
    with pytest.raises(BrokerError, match="owner-only"):
        BrokerClient(socket_path, caller="pi")


@pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX") or os.name == "nt",
    reason="Unix symlink behavior required",
)
def test_broker_rejects_symlinked_or_non_socket_endpoint(broker_root: Path) -> None:
    root = broker_root
    regular = root / "regular"
    regular.write_text("not a socket", encoding="utf-8")
    regular.chmod(0o600)
    with pytest.raises(BrokerError, match="socket"):
        BrokerClient(regular, caller="pi").call("doctor", {})

    real = root / "real"
    real.mkdir(mode=0o700)
    linked = root / "linked"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(BrokerError, match="symbolic"):
        BrokerClient(linked / "echo.sock", caller="pi")


def test_brokered_mcp_validates_semantic_readiness_before_starting_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, Any]]] = []
    started = False

    class FakeBrokerClient:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def call(self, action: str, arguments: Any) -> dict[str, Any]:
            calls.append((action, dict(arguments)))
            return _ready_doctor()

    def fake_run_mcp(*_args: object, **kwargs: object) -> int:
        nonlocal started
        started = True
        assert callable(kwargs["rpc_dispatcher"])
        return 0

    monkeypatch.setattr(agent_cli, "BrokerClient", FakeBrokerClient)
    monkeypatch.setattr(agent_cli, "run_mcp", fake_run_mcp)
    monkeypatch.setattr(
        agent_cli,
        "_open_memory",
        lambda _args: pytest.fail("brokered MCP reopened the profile"),
    )

    result = agent_cli.main(
        [
            "--profile",
            "echo-universal-qwen3-v1",
            "--scope",
            "local-user",
            "--caller",
            "pi",
            "--embedder",
            "ollama",
            "--embedding-model",
            "qwen3-embedding:latest",
            "--embedding-dimension",
            "1024",
            "--broker-socket",
            "/private/tmp/echo-veil-test.sock",
            "mcp",
        ]
    )

    assert result == 0
    assert started is True
    assert calls == [("doctor", {})]


def test_brokered_mcp_rejects_degraded_doctor_before_host_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = False

    class DegradedBrokerClient:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def call(self, _action: str, _arguments: Any) -> dict[str, Any]:
            report = _ready_doctor()
            report["adapter_ready"] = False
            report["embedding"] = {
                "backend": "keyed-lexical",
                "semantic": False,
            }
            return report

    def fail_if_started(*_args: object, **_kwargs: object) -> int:
        nonlocal started
        started = True
        return 0

    monkeypatch.setattr(agent_cli, "BrokerClient", DegradedBrokerClient)
    monkeypatch.setattr(agent_cli, "run_mcp", fail_if_started)

    result = agent_cli.main(
        [
            "--profile",
            "echo-universal-qwen3-v1",
            "--caller",
            "pi",
            "--embedder",
            "ollama",
            "--broker-socket",
            "/private/tmp/echo-veil-test.sock",
            "mcp",
        ]
    )

    assert result == 1
    assert started is False
