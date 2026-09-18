import pytest

from compromised_keys.atomic_io import atomic_write


def test_failure_preserves_previous_file(tmp_path):
    path = tmp_path / "data.csv"
    path.write_text("previous", encoding="utf-8")
    with pytest.raises(OSError), atomic_write(path, encoding="utf-8") as stream:
        stream.write("incomplete")
        raise OSError("disk full")
    assert path.read_text(encoding="utf-8") == "previous"
    assert list(tmp_path.iterdir()) == [path]


def test_success_replaces_file(tmp_path):
    path = tmp_path / "data.csv"
    with atomic_write(path, encoding="utf-8") as stream:
        stream.write("complete")
    assert path.read_text(encoding="utf-8") == "complete"
