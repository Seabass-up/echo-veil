from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np
import pytest

from scripts import locomo_benchmark


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

    def __init__(self, **_kwargs) -> None:
        pass

    def _vector(self, text: str) -> np.ndarray:
        value = np.zeros(self.dimension, dtype=np.float64)
        lowered = text.casefold()
        value[0 if "backup" in lowered else 1 if "passport" in lowered else 2] = 1.0
        return value

    def embed_document(self, text: str) -> np.ndarray:
        return self._vector(text)

    def embed_documents(self, texts: list[str]) -> list[np.ndarray]:
        return [self._vector(text) for text in texts]

    def embed_query(self, text: str) -> np.ndarray:
        return self._vector(text)

    def embed_retrieval_queries(self, text: str) -> tuple[np.ndarray, np.ndarray]:
        value = self._vector(text)
        return value, value.copy()

    def close(self) -> None:
        pass


def _fixture() -> list[dict[str, object]]:
    return [
        {
            "sample_id": "conv-test",
            "conversation": {
                "speaker_a": "Alice",
                "speaker_b": "Bob",
                "session_1_date_time": "1:00 pm on 8 May, 2023",
            },
            "observation": {
                "session_1_observation": {
                    "Alice": [["Encrypted backups are retained for 35 days.", "D1:1"]]
                }
            },
            "qa": [
                {
                    "question": "How long are encrypted backups retained?",
                    "answer": "35 days",
                    "evidence": ["D1:1"],
                    "category": 1,
                }
            ],
        }
    ]


def test_locomo_benchmark_uses_distilled_observations_and_reports_retrieval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dataset = tmp_path / "locomo.json"
    encoded = json.dumps(_fixture()).encode("utf-8")
    dataset.write_bytes(encoded)
    digest = hashlib.sha256(encoded).hexdigest()
    monkeypatch.setattr(locomo_benchmark, "OllamaTextEmbedder", _FakeEmbedder)

    result = locomo_benchmark.main(
        [
            "--dataset",
            str(dataset),
            "--expected-sha256",
            digest,
            "--dimension",
            "32",
        ]
    )

    assert result == 0
    report = json.loads(capsys.readouterr().out)
    assert report["schema"] == "echo-veil-locomo-retrieval-v1"
    assert report["dataset"]["raw_transcripts_ingested"] is False
    assert report["aggregate"]["top_one_rate"] == 1.0
    assert report["aggregate"]["hard_negative_passed"] == 2
    assert report["end_to_end_answer_quality"]["status"] == "not_run"


def test_locomo_benchmark_rejects_dataset_digest_mismatch(tmp_path: Path) -> None:
    dataset = tmp_path / "locomo.json"
    dataset.write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError, match="SHA-256"):
        locomo_benchmark._load_dataset(dataset, "0" * 64)
