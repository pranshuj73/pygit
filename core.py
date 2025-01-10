import os
import hashlib
import zlib
import struct
import collections
from utils import read_file, write_file


IndexEntry = collections.namedtuple('IndexEntry', [
    'ctime_s', 'ctime_n', 'mtime_s', 'mtime_n', 'dev', 'ino', 'mode',
    'uid', 'gid', 'size', 'sha1', 'flags', 'path',
])


def init(repo: str):
    """Create and initialise a new repository with pygit"""
    folders = [
        repo,
        os.path.join(repo, ".pygit", "index"),
        os.path.join(repo, ".pygit", "objs"),
        os.path.join(repo, ".pygit", "refs", "heads"),
        os.path.join(repo, ".pygit", "refs", "remotes"),
    ]

    for folder in folders:
        os.makedirs(folder, exist_ok=True)

    # create and write to the HEAD file
    write_file(os.path.join(repo, ".pygit", "HEAD"), b"ref: refs/heads/main")


def hash_obj(data, type, write=True):
    header = f"{type} {len(data)}".encode()
    full_data = header + b'\x00' + data
    compressed = zlib.compress(full_data)

    sha1_hash = hashlib.sha1(full_data).hexdigest()

    if write:
        path = os.path.join(".pygit", "objs", sha1_hash[:2], sha1_hash[2:])
        os.makedirs(os.path.dirname(path), exist_ok=True)
        write_file(path, compressed)


def find_obj(sha1_prefix):
    """Find and return the object with the given SHA1 prefix."""
    if len(sha1_prefix) < 2:
        raise ValueError("hash prefix must be at least 2 characters")

    obj_dir = os.path.join(".pygit", "objs", sha1_prefix[:2])
    remaining = sha1_prefix[2:]

    objects = [
        name for name in os.listdir(obj_dir)
        if name.startswith(remaining)
    ]

    if not objects:
        raise ValueError(f"object with prefix '{sha1_prefix}' not found")
    elif len(objects) > 1:
        raise ValueError(f"multiple objects with prefix '{sha1_prefix}' found")
    else:
        return os.path.join(obj_dir, objects[0])


def read_obj(sha1_prefix):
    obj = find_obj(sha1_prefix)
    data = zlib.decompress(read_file(obj))
    null_byte_index = data.index(b'\x00')
    header = data[:null_byte_index].decode()
    type_, size = header.split()
    size = int(size)
    data = data[null_byte_index + 1:]

    assert size == len(data), f'expected {size} bytes, got {len(data)}'
    return type_, data


def read_index():
    """Read the index file and return a list of IndexEntry objects."""
    try:
        data = read_file(os.path.join('.pygit', 'index'))
    except Exception:
        return []

    # create a digest of the index file excluding the last 20 bytes
    digest = hashlib.sha1(data[:-20]).digest()

    # check if the digest matches the last 20 bytes of the index file
    # the last 20 bytes of the index file contain the stored sha1 hash
    # if the computed digest doesnt match the stored hash,
    # the file is corrupt or tampered with
    assert digest == data[-20:]

    # get first 12 bytes of the index file in network byte order
    # first 4 bytes are the signature, next 4 bytes are the version
    # last 4 bytes are the number of index entries
    signature, version, num_entries = struct.unpack('!4sLL', data[:12])
    assert signature == b'DIRC', \
        f'invalid index signature: {signature}'
    assert version == 2, f'unknown index {version}'

    # ignore first 12 bytes (used for sign, ver & num_entries)
    # ignroe last 20 bytes (used for sha1 hash)
    entry_data = data[12:-20]
    entries = []

    # loop through the index entries
    i = 0

    # i + 62 because each index entry is 62 bytes long at least
    while (i + 62) < len(entry_data):
        end = i + 62
        fields = struct.unpack('!LLLLLLLLLL20sH', entry_data[i:end])

        path_end = entry_data.find(b'\x00', end)
        path = entry_data[end:path_end].decode()

        # entry is created using the unpacked fields
        # and the path stored in the index file
        index_entry_fields = (fields + (path,))
        entry = IndexEntry(*index_entry_fields)
        entries.append(entry)
        entry_len = ((62 + len(path) + 8) // 8) * 8
        i += entry_len

    assert len(entries) == num_entries, \
        f'expected {num_entries} index entries, got {len(entries)}'

    return entries
