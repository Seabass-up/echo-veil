from __future__ import annotations

import json

from scripts import qualification_benchmark


def test_qualification_benchmark_runs_bounded_scale_and_recovery(
    capsys,
) -> None:
    result = qualification_benchmark.main(
        [
            "--sizes",
            "64",
            "128",
            "--dimension",
            "32",
            "--batch-size",
            "32",
            "--queries",
            "4",
        ]
    )

    assert result == 0
    report = json.loads(capsys.readouterr().out)
    assert report["schema"] == "echo-veil-local-qualification-v1"
    assert report["verdict"] == "pass"
    assert [item["records"] for item in report["scale"]] == [64, 128]
    assert report["concurrent_read_write"]["passed"] is True
    assert report["abrupt_recovery"]["physical_power_loss_claimed"] is False


def test_qualification_benchmark_rejects_unbounded_inputs() -> None:
    parser = qualification_benchmark.build_parser()

    for arguments in (
        ["--sizes", "0"],
        ["--sizes", "100", "100"],
        ["--dimension", "31"],
        ["--batch-size", "1001"],
        ["--queries", "33"],
    ):
        args = parser.parse_args(arguments)
        try:
            qualification_benchmark._validate_args(args)
        except ValueError:
            continue
        raise AssertionError(f"invalid qualification arguments accepted: {arguments}")
