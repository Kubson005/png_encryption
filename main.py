from pathlib import Path

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def read_png_bytes(path: Path) -> bytes:
    data = path.read_bytes()
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("niepoprawny format PNG")
    return data


if __name__ == "__main__":
    source = Path("shark.png")
    png_bytes = read_png_bytes(source)

