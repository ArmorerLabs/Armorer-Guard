from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from setuptools import Distribution, find_packages, setup
from setuptools.command.build_py import build_py as _build_py
from wheel.bdist_wheel import bdist_wheel as _bdist_wheel


ROOT = Path(__file__).resolve().parent


def _binary_name() -> str:
    return "armorer-guard.exe" if os.name == "nt" else "armorer-guard"


def _copy_runtime_artifacts(target_dir: Path) -> None:
    release_dir = ROOT / "target" / "release"
    binary = release_dir / _binary_name()
    if not binary.exists():
        raise RuntimeError(f"expected Guard binary at {binary}")
    target_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(binary, target_dir / binary.name)
    (target_dir / binary.name).chmod(0o755)

    for artifact in release_dir.iterdir():
        name = artifact.name
        is_onnx_runtime = (
            name.startswith("libonnxruntime")
            or name.startswith("onnxruntime")
            or "onnxruntime" in name
        )
        has_runtime_extension = artifact.suffix in {".dylib", ".dll", ".so"} or ".so." in name
        if artifact.is_file() and is_onnx_runtime and has_runtime_extension:
            shutil.copy2(artifact, target_dir / name)


def _cargo_build_command() -> list[str]:
    command = ["cargo", "build", "--release", "--locked"]
    force_onnx = os.environ.get("ARMORER_GUARD_ONNX")
    is_linux_arm64 = sys.platform.startswith("linux") and platform.machine().lower() in {
        "aarch64",
        "arm64",
    }
    if force_onnx == "0" or (force_onnx is None and is_linux_arm64):
        command.append("--no-default-features")
    return command


class build_py(_build_py):
    def run(self) -> None:
        subprocess.run(_cargo_build_command(), cwd=ROOT, check=True)
        target = ROOT / "armorer_guard" / "bin" / _binary_name()
        _copy_runtime_artifacts(target.parent)
        super().run()


class bdist_wheel(_bdist_wheel):
    def finalize_options(self) -> None:
        super().finalize_options()
        self.root_is_pure = False

    def get_tag(self):
        _python, _abi, platform = super().get_tag()
        return "py3", "none", platform


class BinaryDistribution(Distribution):
    def has_ext_modules(self) -> bool:
        return True


setup(
    distclass=BinaryDistribution,
    packages=find_packages(),
    package_data={
        "armorer_guard": [
            "bin/armorer-guard",
            "bin/armorer-guard.exe",
            "bin/*.dylib",
            "bin/*.dll",
            "bin/*.so",
            "bin/*.so.*",
        ]
    },
    cmdclass={"build_py": build_py, "bdist_wheel": bdist_wheel},
)
