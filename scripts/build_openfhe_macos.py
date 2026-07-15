#!/usr/bin/env python3
"""Build a self-contained OpenFHE wheel for Apple Silicon.

The upstream OpenFHE Python wheel is currently published for Ubuntu. This
builder follows the official source-build process, pins both upstream commits,
vendors the OpenFHE/OpenMP dynamic libraries, and emits an architecture-tagged
wheel instead of the unsafe ``py3-none-any`` tag used by binary-only packages
that do not declare their extension modules.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
import textwrap
import urllib.request
from urllib.parse import urlparse
import venv
from pathlib import Path

OPENFHE_TAG = "v1.5.1"
OPENFHE_COMMIT = "1306d14f8c26bb6150d3e6ad54f28dfe1007689e"
OPENFHE_PYTHON_TAG = "v1.5.1.0"
OPENFHE_PYTHON_COMMIT = "4f13e2c3a7e35f73f4816904dabd3a3db47b6e51"
OPENFHE_REPOSITORY = "https://github.com/openfheorg/openfhe-development.git"
OPENFHE_PYTHON_REPOSITORY = "https://github.com/openfheorg/openfhe-python.git"
WHEEL_VERSION = "1.5.1.0"
PYBIND11_VERSION = "3.0.4"


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    capture: bool = False,
) -> str:
    """Run a checked command and optionally return stripped stdout."""
    result = subprocess.run(
        command,
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
    )
    return result.stdout.strip() if capture else ""


def require_command(name: str, installation_hint: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise RuntimeError(f"{name} is required; {installation_hint}")
    return path


def clone_pinned(
    repository: str,
    tag: str,
    commit: str,
    destination: Path,
) -> None:
    if not destination.exists():
        run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--branch",
                tag,
                repository,
                str(destination),
            ]
        )
    if not (destination / ".git").is_dir():
        raise RuntimeError(f"{destination} exists but is not the expected git clone")
    actual = run(["git", "rev-parse", "HEAD"], cwd=destination, capture=True)
    if actual != commit:
        raise RuntimeError(
            f"{destination} is at {actual}, expected pinned commit {commit}"
        )


def configure_and_build(
    source: Path,
    build: Path,
    arguments: list[str],
    jobs: int,
) -> None:
    run(["cmake", "-S", str(source), "-B", str(build), *arguments])
    run(["cmake", "--build", str(build), "--parallel", str(jobs)])
    run(["cmake", "--install", str(build)])


def patch_macos_dependencies(package: Path) -> None:
    extension = next(package.glob("openfhe*.so"))
    libraries = sorted((package / "lib").glob("*.dylib"))
    libomp = package / "lib" / "libomp.dylib"
    run(["install_name_tool", "-id", "@rpath/libomp.dylib", str(libomp)])

    for binary in [extension, *libraries]:
        linked = run(["otool", "-L", str(binary)], capture=True)
        for line in linked.splitlines()[1:]:
            dependency = line.strip().split(" ", 1)[0]
            if dependency.endswith("/libomp.dylib") and dependency != (
                "@rpath/libomp.dylib"
            ):
                run(
                    [
                        "install_name_tool",
                        "-change",
                        dependency,
                        "@rpath/libomp.dylib",
                        str(binary),
                    ]
                )

    rpaths = run(["otool", "-l", str(extension)], capture=True)
    if "@loader_path/lib" not in rpaths:
        raise RuntimeError("OpenFHE extension is missing its bundled-library rpath")
    for binary in [*libraries, extension]:
        run(["codesign", "--force", "--sign", "-", str(binary)])


def write_wheel_project(project: Path, package: Path) -> None:
    project.mkdir(parents=True)
    shutil.copytree(package, project / "openfhe")
    (project / "pyproject.toml").write_text(
        textwrap.dedent(
            """\
            [build-system]
            requires = ["setuptools>=68", "wheel"]
            build-backend = "setuptools.build_meta"
            """
        ),
        encoding="utf-8",
    )
    (project / "setup.py").write_text(
        textwrap.dedent(
            f"""\
            from setuptools import Distribution, setup


            class BinaryDistribution(Distribution):
                def has_ext_modules(self):
                    return True


            setup(
                name="openfhe",
                version="{WHEEL_VERSION}",
                description="Native Apple Silicon wrapper for OpenFHE",
                url="https://github.com/openfheorg/openfhe-python",
                license="BSD-2-Clause",
                packages=["openfhe"],
                package_data={{
                    "openfhe": [
                        "*.so",
                        "lib/*.dylib",
                        "licenses/*",
                        "build-config.txt",
                    ]
                }},
                include_package_data=True,
                python_requires=">=3.10",
                distclass=BinaryDistribution,
                zip_safe=False,
            )
            """
        ),
        encoding="utf-8",
    )


def smoke_test(wheel: Path, build_root: Path) -> None:
    smoke_environment = build_root / "smoke-venv"
    if smoke_environment.exists():
        shutil.rmtree(smoke_environment)
    venv.EnvBuilder(with_pip=True).create(smoke_environment)
    python = smoke_environment / "bin" / "python"
    run([str(python), "-m", "pip", "install", "--no-deps", str(wheel)])
    program = textwrap.dedent(
        """\
        import platform
        import openfhe as fhe

        assert platform.machine() == "arm64"
        params = fhe.CCParamsCKKSRNS()
        params.SetMultiplicativeDepth(2)
        params.SetScalingModSize(50)
        params.SetBatchSize(16)
        params.SetSecurityLevel(fhe.SecurityLevel.HEStd_128_classic)
        context = fhe.GenCryptoContext(params)
        context.Enable(fhe.PKESchemeFeature.PKE)
        context.Enable(fhe.PKESchemeFeature.KEYSWITCH)
        context.Enable(fhe.PKESchemeFeature.LEVELEDSHE)
        context.Enable(fhe.PKESchemeFeature.ADVANCEDSHE)
        keys = context.KeyGen()
        context.EvalSumKeyGen(keys.secretKey)
        vector = [0.6, 0.8]
        plaintext = context.MakeCKKSPackedPlaintext(vector)
        ciphertext = context.Encrypt(keys.publicKey, plaintext)
        products = context.EvalMult(ciphertext, plaintext)
        summed = context.EvalSum(products, len(vector))
        result = context.Decrypt(summed, keys.secretKey)
        result.SetLength(1)
        score = float(result.GetRealPackedValue()[0])
        assert abs(score - 1.0) < 0.01, score
        print(f"native arm64 OpenFHE CKKS score: {score:.12f}")
        """
    )
    run([str(python), "-c", program])


def build(args: argparse.Namespace) -> Path:
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise RuntimeError("this builder requires an Apple Silicon (arm64) Mac")
    if sys.version_info < (3, 10):
        raise RuntimeError("OpenFHE requires Python 3.10 or newer")
    require_command("git", "install the Xcode Command Line Tools")
    require_command("cmake", "run `brew install cmake libomp`")
    require_command("install_name_tool", "install the Xcode Command Line Tools")
    require_command("codesign", "install the Xcode Command Line Tools")
    brew = require_command("brew", "install Homebrew, then run `brew install libomp`")
    libomp_prefix = Path(run([brew, "--prefix", "libomp"], capture=True))
    libomp = libomp_prefix / "lib" / "libomp.dylib"
    if not libomp.is_file():
        raise RuntimeError("libomp is required; run `brew install libomp`")
    libomp_parts = run([brew, "list", "--versions", "libomp"], capture=True).split()
    if len(libomp_parts) != 2:
        raise RuntimeError("could not determine the installed libomp version")
    libomp_version = libomp_parts[1]

    build_root = args.build_root.resolve()
    output_directory = args.output_dir.resolve()
    build_root.mkdir(parents=True, exist_ok=True)
    output_directory.mkdir(parents=True, exist_ok=True)

    openfhe_source = build_root / "openfhe-development"
    python_source = build_root / "openfhe-python"
    clone_pinned(
        OPENFHE_REPOSITORY,
        OPENFHE_TAG,
        OPENFHE_COMMIT,
        openfhe_source,
    )
    clone_pinned(
        OPENFHE_PYTHON_REPOSITORY,
        OPENFHE_PYTHON_TAG,
        OPENFHE_PYTHON_COMMIT,
        python_source,
    )

    prefix = build_root / "prefix"
    configure_and_build(
        openfhe_source,
        build_root / "build-openfhe",
        [
            "-DCMAKE_BUILD_TYPE=Release",
            f"-DCMAKE_INSTALL_PREFIX={prefix}",
            "-DCMAKE_OSX_ARCHITECTURES=arm64",
            "-DBUILD_UNITTESTS=OFF",
            "-DBUILD_EXAMPLES=OFF",
            "-DBUILD_BENCHMARKS=OFF",
            "-DBUILD_STATIC=OFF",
            "-DBUILD_SHARED=ON",
            "-DWITH_OPENMP=ON",
        ],
        args.jobs,
    )

    build_environment = build_root / "build-venv"
    build_python = build_environment / "bin" / "python"
    if not build_python.exists():
        venv.EnvBuilder(with_pip=True).create(build_environment)
    run(
        [
            str(build_python),
            "-m",
            "pip",
            "install",
            f"pybind11=={PYBIND11_VERSION}",
            "setuptools>=68",
            "wheel",
        ]
    )
    pybind11_cmake = run(
        [str(build_python), "-m", "pybind11", "--cmakedir"], capture=True
    )
    wrapper_install = build_root / "wrapper-install"
    configure_and_build(
        python_source,
        build_root
        / f"build-openfhe-python-cp{sys.version_info.major}{sys.version_info.minor}",
        [
            "-DCMAKE_BUILD_TYPE=Release",
            f"-DCMAKE_PREFIX_PATH={prefix};{pybind11_cmake}",
            f"-DCMAKE_INSTALL_PREFIX={wrapper_install}",
            f"-DPython_EXECUTABLE={build_python}",
            f"-DPYTHON_EXECUTABLE_PATH={build_python}",
        ],
        args.jobs,
    )

    package = build_root / "wheel-root" / "openfhe"
    if package.parent.exists():
        shutil.rmtree(package.parent)
    (package / "lib").mkdir(parents=True)
    extensions = list(wrapper_install.glob("openfhe*.so"))
    if len(extensions) != 1:
        raise RuntimeError("expected one compiled OpenFHE Python extension")
    shutil.copy2(extensions[0], package / extensions[0].name)
    shutil.copy2(wrapper_install / "__init__.py", package / "__init__.py")
    for name in (
        "libOPENFHEcore.1.dylib",
        "libOPENFHEbinfhe.1.dylib",
        "libOPENFHEpke.1.dylib",
    ):
        library = prefix / "lib" / name
        if not library.exists():
            raise RuntimeError(f"missing installed OpenFHE library: {library}")
        shutil.copy2(library.resolve(), package / "lib" / library.name)
    shutil.copy2(libomp, package / "lib" / "libomp.dylib")
    licenses = package / "licenses"
    licenses.mkdir()
    shutil.copy2(openfhe_source / "LICENSE", licenses / "OPENFHE-LICENSE.txt")
    shutil.copy2(python_source / "LICENSE", licenses / "OPENFHE-PYTHON-LICENSE.txt")
    shutil.copy2(
        openfhe_source / "third-party" / "cereal" / "LICENSE",
        licenses / "CEREAL-LICENSE.txt",
    )
    libomp_license_url = (
        "https://raw.githubusercontent.com/llvm/llvm-project/"
        f"llvmorg-{libomp_version}/openmp/LICENSE.TXT"
    )
    parsed_license_url = urlparse(libomp_license_url)
    if (
        parsed_license_url.scheme != "https"
        or parsed_license_url.hostname != "raw.githubusercontent.com"
    ):
        raise RuntimeError("LLVM license URL must use the pinned HTTPS origin")
    with urllib.request.urlopen(  # nosec B310 -- scheme and host validated above
        libomp_license_url,
        timeout=30,
    ) as response:
        libomp_license = response.read(100_000)
    if not libomp_license or len(libomp_license) >= 100_000:
        raise RuntimeError("could not retrieve the bounded LLVM OpenMP license")
    (licenses / "LLVM-OPENMP-LICENSE.txt").write_bytes(libomp_license)
    (package / "build-config.txt").write_text(
        textwrap.dedent(
            f"""\
            OPENFHE_TAG={OPENFHE_TAG}
            OPENFHE_COMMIT={OPENFHE_COMMIT}
            OPENFHE_PYTHON_TAG={OPENFHE_PYTHON_TAG}
            OPENFHE_PYTHON_COMMIT={OPENFHE_PYTHON_COMMIT}
            ARCHITECTURE=arm64
            PYTHON={platform.python_version()}
            LIBOMP={libomp_version}
            """
        ),
        encoding="utf-8",
    )
    patch_macos_dependencies(package)

    wheel_project = build_root / "wheel-project"
    if wheel_project.exists():
        shutil.rmtree(wheel_project)
    write_wheel_project(wheel_project, package)
    run(
        [
            str(build_python),
            "-m",
            "pip",
            "wheel",
            "--no-build-isolation",
            "--no-deps",
            "--wheel-dir",
            str(output_directory),
            str(wheel_project),
        ]
    )
    wheels = sorted(output_directory.glob("openfhe-*.whl"), key=os.path.getmtime)
    if not wheels:
        raise RuntimeError("OpenFHE wheel was not produced")
    wheel = wheels[-1]
    if "none-any" in wheel.name or "arm64" not in wheel.name:
        raise RuntimeError(f"wheel has an unsafe platform tag: {wheel.name}")
    if not args.skip_smoke_test:
        smoke_test(wheel, build_root)
    return wheel


def parse_args() -> argparse.Namespace:
    repository = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Build and smoke-test OpenFHE for an Apple Silicon Mac."
    )
    parser.add_argument(
        "--build-root",
        type=Path,
        default=repository / "build" / "openfhe-macos-arm64",
        help="reusable source/build cache",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=repository / "dist",
        help="directory that receives the wheel",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=min(os.cpu_count() or 2, 8),
        help="parallel compiler jobs",
    )
    parser.add_argument(
        "--skip-smoke-test",
        action="store_true",
        help="build the wheel without installing it in a clean test environment",
    )
    arguments = parser.parse_args()
    if arguments.jobs <= 0:
        parser.error("--jobs must be positive")
    return arguments


def main() -> int:
    try:
        wheel = build(parse_args())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"OpenFHE Apple Silicon build failed: {exc}", file=sys.stderr)
        return 1
    print(f"Built and verified: {wheel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
