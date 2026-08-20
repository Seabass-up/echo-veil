from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np
import pytest

from scripts import longmemeval_benchmark


class _FakeEmbedder:
    identity = (
        "ollama:qwen3-embedding:latest@sha256:"
        + "a" * 64
        + ":dimension:32:instruction:"
        + "b" * 64
    )
    name = "ollama"
    model = "qwen3-embedding:latest"
    dimension = 32
    semantic = True
    default_min_score = 0.44

    def __init__(self, **_kwargs: object) -> None:
        pass

    def _vector(self, text: str) -> np.ndarray[Any, np.dtype[np.float64]]:
        value = np.zeros(self.dimension, dtype=np.float64)
        value[0 if "backup" in text.casefold() else 1] = 1.0
        return value

    def embed_document(self, text: str) -> np.ndarray[Any, np.dtype[np.float64]]:
        return self._vector(text)

    def embed_documents(
        self, texts: list[str]
    ) -> list[np.ndarray[Any, np.dtype[np.float64]]]:
        return [self._vector(text) for text in texts]

    def embed_query(self, text: str) -> np.ndarray[Any, np.dtype[np.float64]]:
        return self._vector(text)

    def embed_retrieval_queries(
        self, text: str
    ) -> tuple[
        np.ndarray[Any, np.dtype[np.float64]],
        np.ndarray[Any, np.dtype[np.float64]],
    ]:
        value = self._vector(text)
        return value, value.copy()

    def close(self) -> None:
        pass


class _FakeGenerator:
    model = "qwen3.8:27b-mlx"
    model_digest = "c" * 64
    capture_calls: list[Sequence[Mapping[str, Any]]] = []

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        type(self).capture_calls = []

    def capture(self, sessions: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        type(self).capture_calls.append(sessions)
        encoded = json.dumps(sessions)
        assert "How long are encrypted backups retained?" not in encoded
        assert '"answer"' not in encoded
        return {
            "records": [
                {
                    "capture_unit_id": str(sessions[0]["capture_unit_id"]),
                    "topic": "encrypted backup retention",
                    "payload": "Encrypted backups are retained for 35 days.",
                }
            ]
        }

    def answer(
        self,
        question: str,
        evidence: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        assert question == "How long are encrypted backups retained?"
        assert any("35 days" in str(item.get("payload")) for item in evidence)
        return {"answer": "35 days", "supported": True}

    def close(self) -> None:
        pass


class _FailingReaderGenerator(_FakeGenerator):
    def answer(
        self,
        question: str,
        evidence: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        raise RuntimeError("synthetic invalid reader output")


class _UnsupportedGuessGenerator(_FakeGenerator):
    def answer(
        self,
        question: str,
        evidence: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        return {"answer": "35 days", "supported": False}


class _CloseTrackingGenerator(_FakeGenerator):
    closed = False

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        super().__init__()
        type(self).closed = False

    def close(self) -> None:
        type(self).closed = True


class _MalformedBatchGenerator(_FakeGenerator):
    def capture(self, sessions: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        type(self).capture_calls.append(sessions)
        identifier = str(sessions[0]["capture_unit_id"])
        if len(sessions) > 1:
            return {
                "records": [
                    {
                        "session_id": identifier,
                        "topic": "invalid batch",
                        "payload": "The batch response used the wrong identifier field.",
                    }
                ]
            }
        return {
            "records": [
                {
                    "capture_unit_id": identifier,
                    "topic": "bounded single-unit retry",
                    "payload": f"Recovered capture unit {identifier}.",
                }
            ]
        }


class _MalformedStructuredBatchGenerator(_MalformedBatchGenerator):
    def capture(self, sessions: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        type(self).capture_calls.append(sessions)
        if len(sessions) > 1:
            raise longmemeval_benchmark.StructuredOutputError(
                "synthetic malformed JSON output"
            )
        identifier = str(sessions[0]["capture_unit_id"])
        return {
            "records": [
                {
                    "capture_unit_id": identifier,
                    "topic": "bounded structured-output retry",
                    "payload": f"Recovered capture unit {identifier}.",
                }
            ]
        }


class _FailAfterFirstBatchGenerator(_FakeGenerator):
    def capture(self, sessions: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        if type(self).capture_calls:
            type(self).capture_calls.append(sessions)
            raise RuntimeError("synthetic transport outage")
        return super().capture(sessions)


class _OutageGenerator(_FakeGenerator):
    def capture(self, sessions: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        type(self).capture_calls.append(sessions)
        raise RuntimeError("synthetic transport outage")


def _fixture() -> list[dict[str, object]]:
    return [
        {
            "question_id": "a1b2c3d4",
            "question_type": "single-session-user",
            "question": "How long are encrypted backups retained?",
            "answer": "35 days",
            "question_date": "2023/05/09 (Tue) 13:00",
            "haystack_session_ids": ["answer_session_1"],
            "haystack_dates": ["2023/05/08 (Mon) 13:00"],
            "haystack_sessions": [
                [
                    {
                        "role": "user",
                        "content": "Please define encrypted backup retention.",
                    },
                    {
                        "role": "assistant",
                        "content": "Encrypted backups are retained for 35 days.",
                        "has_answer": True,
                    },
                ]
            ],
            "answer_session_ids": ["answer_session_1"],
        }
    ]


def test_longmemeval_query_blind_capture_retrieval_and_reader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dataset = tmp_path / "longmemeval.json"
    encoded = json.dumps(_fixture()).encode("utf-8")
    dataset.write_bytes(encoded)
    digest = hashlib.sha256(encoded).hexdigest()
    monkeypatch.setattr(longmemeval_benchmark, "OllamaJsonGenerator", _FakeGenerator)
    monkeypatch.setattr(longmemeval_benchmark, "OllamaTextEmbedder", _FakeEmbedder)

    result = longmemeval_benchmark.main(
        [
            "--dataset",
            str(dataset),
            "--expected-sha256",
            digest,
            "--limit-questions",
            "1",
            "--embedding-dimension",
            "32",
            "--run-reader",
            "--authorize-supporting-payloads",
        ]
    )

    assert result == 0
    report = json.loads(capsys.readouterr().out)
    assert report["schema"] == "echo-veil-longmemeval-pilot-v1"
    assert report["dataset"]["raw_transcripts_ingested"] is False
    assert report["dataset"]["capture_query_blind"] is True
    assert report["dataset"]["gold_sessions_used_for_capture"] is False
    assert report["dataset"]["gold_turn_markers_used_for_capture"] is False
    assert report["dataset"]["gold_turn_markers_used_for_evaluation"] is True
    assert report["dataset"]["validated_inventory"] == {
        "duplicate_session_ids_disambiguated": 0,
        "empty_messages_ignored": 0,
        "answer_marked_messages_for_evaluation": 1,
        "questions_with_answer_markers_for_evaluation": 1,
        "question_types": {
            question_type: int(question_type == "single-session-user")
            for question_type in longmemeval_benchmark.QUESTION_TYPES
        },
        "questions": 1,
        "sessions": 1,
    }
    assert report["capture"]["cache_contains_plaintext_seed_crystals"] is False
    assert report["capture"]["cache_schema"] is None
    assert report["sampling"] == {
        "query_blind": True,
        "selected_questions": 1,
        "strategy": "stratified",
    }
    assert report["retrieval_evaluation_unit"] == "gold-source-session-provenance"
    assert report["capture"]["partition_contract"].startswith(
        "query-blind-contiguous-message-windows-v2:"
    )
    assert len(report["capture"]["contract_sha256"]) == 64
    assert report["capture"]["recovery_contract"].endswith("fail-closed")
    assert report["reader"]["enabled"] is True
    assert report["reader"]["output_contract"] == (
        "strict-json-object-v1:accept-one-exact-json-fence"
    )
    assert len(report["reader"]["contract_sha256"]) == 64
    assert report["aggregate"]["gold_session_top_one_rate"] == 1.0
    assert report["aggregate"]["mean_gold_session_recall_at_k"] == 1.0
    assert report["aggregate"]["gold_answer_unit_questions"] == 1
    assert report["aggregate"]["gold_answer_unit_top_one_rate"] == 1.0
    assert report["aggregate"]["mean_gold_answer_unit_recall_at_k"] == 1.0
    assert report["aggregate"]["capture_cache_hits"] == 0
    assert report["aggregate"]["local_reader"]["normalized_exact_rate"] == 1.0
    assert report["aggregate"]["local_reader"]["supported_rate"] == 1.0
    assert len(_FakeGenerator.capture_calls) == 1


def test_longmemeval_precision_at_k_penalizes_early_abstention(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    row = _fixture()[0]
    row["haystack_session_ids"] = [f"session_{index}" for index in range(6)]
    row["haystack_dates"] = ["2023/05/08 (Mon) 13:00"] * 6
    row["haystack_sessions"] = [
        [
            {"role": "user", "content": f"Session {index} context."},
            {
                "role": "assistant",
                "content": (
                    "Encrypted backups are retained for 35 days."
                    if index == 0
                    else f"Unrelated durable fact {index}."
                ),
                **({"has_answer": True} if index == 0 else {}),
            },
        ]
        for index in range(6)
    ]
    row["answer_session_ids"] = ["session_0"]
    dataset = tmp_path / "longmemeval.json"
    encoded = json.dumps([row]).encode("utf-8")
    dataset.write_bytes(encoded)
    monkeypatch.setattr(longmemeval_benchmark, "OllamaJsonGenerator", _FakeGenerator)
    monkeypatch.setattr(longmemeval_benchmark, "OllamaTextEmbedder", _FakeEmbedder)

    assert (
        longmemeval_benchmark.main(
            [
                "--dataset",
                str(dataset),
                "--expected-sha256",
                hashlib.sha256(encoded).hexdigest(),
                "--limit-questions",
                "1",
                "--embedding-dimension",
                "32",
                "--top-k",
                "5",
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["questions"][0]["returned_sessions"] == 1
    assert report["questions"][0]["gold_session_precision_at_k"] == 0.2
    assert report["questions"][0]["exact_retry_deduplications"] == 1
    assert report["questions"][0]["cross_session_exact_deduplications"] == 1
    assert report["aggregate"]["exact_retry_deduplications"] == 1
    assert report["aggregate"]["cross_session_exact_deduplications"] == 1


def test_longmemeval_does_not_infer_missing_gold_answer_units(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rows = _fixture()
    del rows[0]["haystack_sessions"][0][1]["has_answer"]  # type: ignore[index]
    dataset = tmp_path / "longmemeval.json"
    encoded = json.dumps(rows).encode("utf-8")
    dataset.write_bytes(encoded)
    monkeypatch.setattr(longmemeval_benchmark, "OllamaJsonGenerator", _FakeGenerator)
    monkeypatch.setattr(longmemeval_benchmark, "OllamaTextEmbedder", _FakeEmbedder)

    assert (
        longmemeval_benchmark.main(
            [
                "--dataset",
                str(dataset),
                "--expected-sha256",
                hashlib.sha256(encoded).hexdigest(),
                "--limit-questions",
                "1",
                "--embedding-dimension",
                "32",
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    question = report["questions"][0]
    assert question["gold_answer_unit_markers_available"] is False
    assert question["gold_answer_unit_top_one"] is None
    assert question["gold_answer_unit_recall_at_k"] is None
    assert report["aggregate"]["gold_answer_unit_questions"] == 0
    assert report["aggregate"]["gold_answer_unit_top_one_rate"] is None


def test_longmemeval_stratified_sampling_covers_question_types() -> None:
    rows = [
        {"question_id": f"{index:08x}", "question_type": question_type}
        for index, question_type in enumerate(longmemeval_benchmark.QUESTION_TYPES)
    ]
    rows.extend(
        {
            "question_id": f"{index + 100:08x}",
            "question_type": question_type,
        }
        for index, question_type in enumerate(longmemeval_benchmark.QUESTION_TYPES)
    )

    selected = longmemeval_benchmark._select_rows(rows, 6, "stratified")

    assert {row["question_type"] for row in selected} == set(
        longmemeval_benchmark.QUESTION_TYPES
    )
    assert selected == longmemeval_benchmark._select_rows(rows, 6, "stratified")


def test_longmemeval_capture_cache_avoids_repeat_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dataset = tmp_path / "longmemeval.json"
    cache = tmp_path / "capture-cache.json"
    encoded = json.dumps(_fixture()).encode("utf-8")
    dataset.write_bytes(encoded)
    digest = hashlib.sha256(encoded).hexdigest()
    monkeypatch.setattr(longmemeval_benchmark, "OllamaJsonGenerator", _FakeGenerator)
    monkeypatch.setattr(longmemeval_benchmark, "OllamaTextEmbedder", _FakeEmbedder)
    arguments = [
        "--dataset",
        str(dataset),
        "--expected-sha256",
        digest,
        "--limit-questions",
        "1",
        "--embedding-dimension",
        "32",
        "--capture-cache",
        str(cache),
    ]

    assert longmemeval_benchmark.main(arguments) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["questions"][0]["capture_cache_hit"] is False
    assert first["capture"]["cache_contains_plaintext_seed_crystals"] is True
    assert first["capture"]["cache_schema"] == (
        "echo-veil-longmemeval-capture-cache-v4"
    )
    assert len(_FakeGenerator.capture_calls) == 1

    assert longmemeval_benchmark.main(arguments) == 0
    second = json.loads(capsys.readouterr().out)
    assert second["questions"][0]["capture_cache_hit"] is True
    assert second["questions"][0]["capture_batches"] == 0
    assert second["aggregate"]["capture_cache_hits"] == 1
    assert second["questions"][0]["setup_ms"] >= second["questions"][0]["ingest_ms"]
    assert len(_FakeGenerator.capture_calls) == 0
    assert any("plaintext seed crystals" in item for item in second["limitations"])


def test_longmemeval_rejects_dataset_digest_mismatch(tmp_path: Path) -> None:
    dataset = tmp_path / "longmemeval.json"
    dataset.write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError, match="SHA-256"):
        longmemeval_benchmark._load_dataset(dataset, "0" * 64)


def test_longmemeval_generator_rejects_noncanonical_response_length() -> None:
    class Response:
        status = 200

        @staticmethod
        def getheader(name: str, default: str | None = None) -> str | None:
            return "application/json" if name == "Content-Type" else "-1"

        @staticmethod
        def read(_maximum: int) -> bytes:
            raise AssertionError("invalid response length must fail before body read")

    class Connection:
        @staticmethod
        def request(*_args: object, **_kwargs: object) -> None:
            return None

        @staticmethod
        def getresponse() -> Response:
            return Response()

    generator = object.__new__(longmemeval_benchmark.OllamaJsonGenerator)
    generator._connection = Connection()  # type: ignore[assignment]  # noqa: SLF001
    generator._host = "127.0.0.1"  # noqa: SLF001
    generator._port = 11434  # noqa: SLF001
    generator._timeout = 1.0  # noqa: SLF001
    generator._request_count = 0  # noqa: SLF001

    with pytest.raises(RuntimeError, match="invalid content length"):
        generator._request_json("GET", "/api/tags")  # noqa: SLF001


def test_longmemeval_reader_only_accepts_one_exact_json_fence() -> None:
    fenced = '```json\n{"answer":"The Glass Menagerie","supported":true}\n```'

    parsed, normalized = longmemeval_benchmark._parse_model_json(
        fenced,
        accept_exact_json_fence=True,
    )

    assert parsed == {"answer": "The Glass Menagerie", "supported": True}
    assert normalized is True
    with pytest.raises(longmemeval_benchmark.StructuredOutputError):
        longmemeval_benchmark._parse_model_json(
            fenced,
            accept_exact_json_fence=False,
        )
    with pytest.raises(longmemeval_benchmark.StructuredOutputError):
        longmemeval_benchmark._parse_model_json(
            f"prefix\n{fenced}",
            accept_exact_json_fence=True,
        )


def test_longmemeval_closes_generator_when_embedder_initialization_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset = tmp_path / "longmemeval.json"
    encoded = json.dumps(_fixture()).encode("utf-8")
    dataset.write_bytes(encoded)

    def fail_embedder(**_kwargs: object) -> None:
        raise RuntimeError("synthetic embedding initialization failure")

    monkeypatch.setattr(
        longmemeval_benchmark,
        "OllamaJsonGenerator",
        _CloseTrackingGenerator,
    )
    monkeypatch.setattr(longmemeval_benchmark, "OllamaTextEmbedder", fail_embedder)

    with pytest.raises(RuntimeError, match="embedding initialization failure"):
        longmemeval_benchmark.main(
            [
                "--dataset",
                str(dataset),
                "--expected-sha256",
                hashlib.sha256(encoded).hexdigest(),
                "--limit-questions",
                "1",
            ]
        )
    assert _CloseTrackingGenerator.closed is True


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink input contract")
def test_longmemeval_rejects_symlinked_dataset(tmp_path: Path) -> None:
    dataset = tmp_path / "longmemeval.json"
    dataset.write_text("[]", encoding="utf-8")
    linked = tmp_path / "linked.json"
    linked.symlink_to(dataset)

    with pytest.raises(ValueError, match="non-symlink"):
        longmemeval_benchmark._load_dataset(linked, hashlib.sha256(b"[]").hexdigest())


def test_longmemeval_capture_rejects_verbatim_and_unknown_sessions() -> None:
    content = "A" * 120
    session = longmemeval_benchmark.Session(
        session_id="session_1",
        source_session_id="session_1",
        date="2023/05/08 (Mon) 13:00",
        timestamp=1.0,
        messages=({"role": "user", "content": content},),
    )
    unit = longmemeval_benchmark._capture_units([session])[0]
    records, rejected = longmemeval_benchmark._capture_records(
        {
            "records": [
                {
                    "capture_unit_id": unit.capture_unit_id,
                    "topic": "copied input",
                    "payload": content,
                }
            ]
        },
        [unit],
    )
    assert records == []
    assert rejected == 1

    with pytest.raises(ValueError, match="unknown capture unit"):
        longmemeval_benchmark._capture_records(
            {
                "records": [
                    {
                        "capture_unit_id": "capture-unknown-000",
                        "topic": "invalid",
                        "payload": "This record points outside its capture batch.",
                    }
                ]
            },
            [unit],
        )


def test_longmemeval_partitions_long_sessions_without_query_or_gold_markers() -> None:
    session = longmemeval_benchmark.Session(
        session_id="session_1",
        source_session_id="session_1",
        date="2023/05/08 (Mon) 13:00",
        timestamp=1.0,
        messages=tuple(
            {
                "role": "user" if index % 2 == 0 else "assistant",
                "content": f"Durable exchange {index}.",
            }
            for index in range(14)
        ),
    )

    units = longmemeval_benchmark._capture_units([session])

    assert [len(unit.messages) for unit in units] == [4, 4, 4, 2]
    assert len({unit.capture_unit_id for unit in units}) == 4
    assert all(unit.source is session for unit in units)
    encoded = json.dumps([unit.public_capture_value() for unit in units])
    assert "future question" not in encoded
    assert "has_answer" not in encoded
    assert "source_session_id" not in encoded


def test_longmemeval_rejects_too_many_capture_units(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = longmemeval_benchmark.Session(
        session_id="session_1",
        source_session_id="session_1",
        date="2023/05/08 (Mon) 13:00",
        timestamp=1.0,
        messages=tuple(
            {"role": "user", "content": f"Durable exchange {index}."}
            for index in range(14)
        ),
    )
    monkeypatch.setattr(longmemeval_benchmark, "MAX_CAPTURE_UNITS_PER_QUESTION", 2)

    with pytest.raises(ValueError, match="per-question review bound"):
        longmemeval_benchmark._capture_batches([session])


def test_longmemeval_bisects_malformed_batches_into_bounded_units() -> None:
    session = longmemeval_benchmark.Session(
        session_id="session_1",
        source_session_id="session_1",
        date="2023/05/08 (Mon) 13:00",
        timestamp=1.0,
        messages=tuple(
            {"role": "user", "content": f"Durable exchange {index}."}
            for index in range(24)
        ),
    )
    units = longmemeval_benchmark._capture_units([session])
    generator = _MalformedBatchGenerator()

    records, rejected, recoveries = longmemeval_benchmark._capture_validated(
        generator, units
    )

    assert len(units) == 6
    assert len(records) == 6
    assert rejected == 0
    assert recoveries == 5
    assert len(_MalformedBatchGenerator.capture_calls) == 11


def test_longmemeval_bisects_malformed_json_without_retrying_outages() -> None:
    session = longmemeval_benchmark.Session(
        session_id="session_1",
        source_session_id="session_1",
        date="2023/05/08 (Mon) 13:00",
        timestamp=1.0,
        messages=tuple(
            {"role": "user", "content": f"Durable exchange {index}."}
            for index in range(24)
        ),
    )
    units = longmemeval_benchmark._capture_units([session])
    generator = _MalformedStructuredBatchGenerator()

    records, rejected, recoveries = longmemeval_benchmark._capture_validated(
        generator, units
    )

    assert len(records) == 6
    assert rejected == 0
    assert recoveries == 5
    assert len(_MalformedStructuredBatchGenerator.capture_calls) == 11

    with pytest.raises(RuntimeError, match="synthetic transport outage"):
        longmemeval_benchmark._capture_validated(_OutageGenerator(), units)
    assert len(_OutageGenerator.capture_calls) == 1


def test_longmemeval_progress_is_interactive_and_payload_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class InteractiveBuffer(io.StringIO):
        def isatty(self) -> bool:
            return True

    stream = InteractiveBuffer()
    monkeypatch.setattr(longmemeval_benchmark.sys, "stderr", stream)

    longmemeval_benchmark._emit_capture_progress(
        question_id="a1b2c3d4",
        completed_units=4,
        total_units=10,
        records=3,
        recoveries=1,
    )

    assert json.loads(stream.getvalue()) == {
        "completed_units": 4,
        "event": "longmemeval-capture-progress-v1",
        "question_id": "a1b2c3d4",
        "records": 3,
        "recovery_attempts": 1,
        "total_units": 10,
    }


def test_longmemeval_resumes_from_atomic_batch_checkpoint(tmp_path: Path) -> None:
    row = _fixture()[0]
    row["haystack_sessions"] = [
        [
            {
                "role": "user" if index % 2 == 0 else "assistant",
                "content": f"Encrypted backup durable exchange {index}.",
            }
            for index in range(30)
        ]
    ]
    cache_path = tmp_path / "capture-cache.json"
    cache = longmemeval_benchmark.CaptureCache(
        cache_path,
        dataset_sha256="d" * 64,
        capture_model="qwen3.8:27b-mlx",
        capture_model_sha256="c" * 64,
    )
    sessions = longmemeval_benchmark._parse_question(row)[3]
    source_sha256 = hashlib.sha256(
        longmemeval_benchmark._canonical_json_bytes(
            [session.public_capture_value() for session in sessions]
        )
    ).hexdigest()

    with pytest.raises(RuntimeError, match="synthetic transport outage"):
        longmemeval_benchmark._run_question(
            tmp_path / "state",
            row,
            generator=_FailAfterFirstBatchGenerator(),
            embedder=_FakeEmbedder(),
            dataset_digest="d" * 64,
            top_k=5,
            retrieval_mode="supporting",
            run_reader=False,
            authorize_supporting_payloads=False,
            capture_cache=cache,
        )

    cache = longmemeval_benchmark.CaptureCache(
        cache_path,
        dataset_sha256="d" * 64,
        capture_model="qwen3.8:27b-mlx",
        capture_model_sha256="c" * 64,
    )
    partial = cache.get("a1b2c3d4", source_sha256)
    assert partial is not None
    assert partial["complete"] is False
    assert partial["completed_capture_units"] == 4
    assert partial["capture_units"] == 8

    generator = _FakeGenerator()
    report = longmemeval_benchmark._run_question(
        tmp_path / "state",
        row,
        generator=generator,
        embedder=_FakeEmbedder(),
        dataset_digest="d" * 64,
        top_k=5,
        retrieval_mode="supporting",
        run_reader=False,
        authorize_supporting_payloads=False,
        capture_cache=cache,
    )

    assert report["capture_cache_hit"] is True
    assert report["capture_cache_complete_hit"] is False
    assert report["capture_batches"] == 1
    assert len(_FakeGenerator.capture_calls) == 1
    completed = cache.get("a1b2c3d4", source_sha256)
    assert completed is not None
    assert completed["complete"] is True
    assert completed["completed_capture_units"] == 8


def test_longmemeval_reader_requires_explicit_supporting_authorization(
    tmp_path: Path,
) -> None:
    dataset = tmp_path / "longmemeval.json"
    encoded = json.dumps(_fixture()).encode("utf-8")
    dataset.write_bytes(encoded)

    with pytest.raises(ValueError, match="explicit supporting-payload"):
        longmemeval_benchmark.main(
            [
                "--dataset",
                str(dataset),
                "--expected-sha256",
                hashlib.sha256(encoded).hexdigest(),
                "--limit-questions",
                "1",
                "--run-reader",
            ]
        )


def test_longmemeval_scores_reader_failure_instead_of_aborting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dataset = tmp_path / "longmemeval.json"
    encoded = json.dumps(_fixture()).encode("utf-8")
    dataset.write_bytes(encoded)
    monkeypatch.setattr(
        longmemeval_benchmark,
        "OllamaJsonGenerator",
        _FailingReaderGenerator,
    )
    monkeypatch.setattr(longmemeval_benchmark, "OllamaTextEmbedder", _FakeEmbedder)

    assert (
        longmemeval_benchmark.main(
            [
                "--dataset",
                str(dataset),
                "--expected-sha256",
                hashlib.sha256(encoded).hexdigest(),
                "--limit-questions",
                "1",
                "--run-reader",
                "--authorize-supporting-payloads",
                "--embedding-dimension",
                "32",
            ]
        )
        == 0
    )

    report = json.loads(capsys.readouterr().out)
    assert report["questions"][0]["reader"]["status"] == "failed-local-reader"
    assert report["aggregate"]["local_reader"]["questions"] == 1
    assert report["aggregate"]["local_reader"]["failures"] == 1
    assert report["aggregate"]["local_reader"]["normalized_exact_rate"] == 0.0


def test_longmemeval_never_credits_an_unsupported_reader_guess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dataset = tmp_path / "longmemeval.json"
    encoded = json.dumps(_fixture()).encode("utf-8")
    dataset.write_bytes(encoded)
    monkeypatch.setattr(
        longmemeval_benchmark,
        "OllamaJsonGenerator",
        _UnsupportedGuessGenerator,
    )
    monkeypatch.setattr(longmemeval_benchmark, "OllamaTextEmbedder", _FakeEmbedder)

    assert (
        longmemeval_benchmark.main(
            [
                "--dataset",
                str(dataset),
                "--expected-sha256",
                hashlib.sha256(encoded).hexdigest(),
                "--limit-questions",
                "1",
                "--run-reader",
                "--authorize-supporting-payloads",
                "--embedding-dimension",
                "32",
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    reader = report["questions"][0]["reader"]
    assert reader["status"] == "failed-local-reader"
    assert reader["normalized_exact"] is False
    assert reader["token_f1"] == 0.0


def test_longmemeval_capture_cache_is_owner_only_bound_and_tamper_evident(
    tmp_path: Path,
) -> None:
    path = tmp_path / "capture-cache.json"
    cache = longmemeval_benchmark.CaptureCache(
        path,
        dataset_sha256="a" * 64,
        capture_model="capture-model:latest",
        capture_model_sha256="b" * 64,
    )
    entry = {
        "source_sha256": "c" * 64,
        "capture_elapsed_ms": 12.5,
        "capture_recovery_attempts": 0,
        "records": [
            {
                "capture_unit_id": "capture-unit-1",
                "topic": "backup retention",
                "payload": "Backups are retained for 35 days.",
            }
        ],
        "capture_units": 1,
        "completed_capture_units": 1,
        "complete": True,
        "verbatim_capture_rejections": 0,
    }
    cache.put("a1b2c3d4", entry)

    assert path.stat().st_mode & 0o777 == 0o600
    reopened = longmemeval_benchmark.CaptureCache(
        path,
        dataset_sha256="a" * 64,
        capture_model="capture-model:latest",
        capture_model_sha256="b" * 64,
    )
    assert reopened.get("a1b2c3d4", "c" * 64) == entry

    decoded = json.loads(path.read_text(encoding="utf-8"))
    assert decoded["schema"] == "echo-veil-longmemeval-capture-cache-v4"
    assert len(decoded["capture_contract_sha256"]) == 64
    decoded["questions"]["a1b2c3d4"]["records"][0]["payload"] = "tampered"
    path.write_text(json.dumps(decoded), encoding="utf-8")
    os.chmod(path, 0o600)
    with pytest.raises(ValueError, match="integrity"):
        longmemeval_benchmark.CaptureCache(
            path,
            dataset_sha256="a" * 64,
            capture_model="capture-model:latest",
            capture_model_sha256="b" * 64,
        )
