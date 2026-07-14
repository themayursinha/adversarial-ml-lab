"""Dependency-boundary tests for the default package and optional features."""

from pathlib import Path


def _project_dependency_sections() -> tuple[str, str]:
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    core = pyproject.split("dependencies = [", 1)[1].split("]", 1)[0].lower()
    optional = pyproject.split("[project.optional-dependencies]", 1)[1].lower()
    return core, optional


def test_heavy_ml_dependencies_are_not_installed_by_default() -> None:
    core, _ = _project_dependency_sections()
    requirements = Path("requirements.txt").read_text(encoding="utf-8").lower()

    for package in ("torch", "torchvision", "sentence-transformers", "wandb"):
        assert package not in core
        assert package not in requirements


def test_optional_extras_define_rag_vision_and_tracking_dependencies() -> None:
    _, optional = _project_dependency_sections()

    assert 'rag = [\n    "sentence-transformers>=3.0.0"' in optional
    assert 'vision = [\n    "torch>=2.12.1",\n    "torchvision' in optional
    assert 'tracking = [\n    "wandb>=0.16.0"' in optional


def test_hashed_docker_requirements_exclude_heavy_ml_dependencies() -> None:
    hashed = Path("requirements-hashed.txt").read_text(encoding="utf-8").lower()

    for package in ("torch", "torchvision", "sentence-transformers", "wandb"):
        assert f"{package}==" not in hashed
