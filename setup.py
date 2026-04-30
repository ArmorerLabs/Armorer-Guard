from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from setuptools import find_packages, setup
from setuptools.command.build_py import build_py as _build_py
from wheel.bdist_wheel import bdist_wheel as _bdist_wheel


ROOT = Path(__file__).resolve().parent


def _binary_name() -> str:
    return "armorer-guard.exe" if os.name == "nt" else "armorer-guard"


class build_py(_build_py):
    def run(self) -> None:
        subprocess.run(["cargo", "build", "--release", "--locked"], cwd=ROOT, check=True)
        source = ROOT / "target" / "release" / _binary_name()
        if not source.exists():
            raise RuntimeError(f"expected Guard binary at {source}")
        target = ROOT / "armorer_guard" / "bin" / _binary_name()
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        target.chmod(0o755)
        super().run()


class bdist_wheel(_bdist_wheel):
    def finalize_options(self) -> None:
        super().finalize_options()
        self.root_is_pure = False

    def get_tag(self):
        _python, _abi, platform = super().get_tag()
        return "py3", "none", platform


setup(
    packages=find_packages(),
    package_data={"armorer_guard": ["bin/armorer-guard", "bin/armorer-guard.exe"]},
    cmdclass={"build_py": build_py, "bdist_wheel": bdist_wheel},
)
