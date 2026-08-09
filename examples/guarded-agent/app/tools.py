"""A real, sandboxed tool used by the guarded-agent example."""

from __future__ import annotations

from pathlib import Path
from typing import TypedDict


class RecordMatch(TypedDict):
    record_id: str
    snippet: str


class RecordStore:
    """Store demo records beneath one temporary root."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def create(self, record_id: str, contents: str) -> Path:
        path = self._path(record_id)
        path.write_text(contents, encoding="utf-8")
        return path

    def list_records(self) -> list[str]:
        return [f"record/{path.stem}" for path in sorted(self.root.glob("*.txt"))]

    def read(self, record_id: str) -> str | None:
        path = self._path(record_id)
        if not path.exists():
            return None
        return path.read_text(encoding="utf-8")

    def search(self, query: str) -> list[RecordMatch]:
        normalized_query = query.strip().casefold()
        if not normalized_query:
            raise ValueError("search query must not be empty")
        matches: list[RecordMatch] = []
        for record_id in self.list_records():
            contents = self.read(record_id)
            if contents is not None and normalized_query in contents.casefold():
                matches.append(
                    {
                        "record_id": record_id,
                        "snippet": contents[:160].replace("\n", " "),
                    }
                )
        return matches

    def delete(self, record_id: str) -> bool:
        path = self._path(record_id)
        existed = path.exists()
        path.unlink(missing_ok=True)
        return existed and not path.exists()

    def exists(self, record_id: str) -> bool:
        return self._path(record_id).exists()

    def _path(self, record_id: str) -> Path:
        prefix = "record/"
        if not record_id.startswith(prefix):
            raise ValueError("record IDs must start with 'record/'")
        name = record_id.removeprefix(prefix)
        if not name or not all(
            character.isalnum() or character in "-_" for character in name
        ):
            raise ValueError("record IDs may contain only letters, digits, '-' and '_'")
        return self.root / f"{name}.txt"
