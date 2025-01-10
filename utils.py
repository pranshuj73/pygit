def read_file(path: str):
    """Read contents of a file in binary mode."""
    with open(path, "rb") as f:
        return f.read()


def write_file(path: str, data: bytes):
    """Write data to a file in binary mode."""
    with open(path, "wb") as f:
        f.write(data)
