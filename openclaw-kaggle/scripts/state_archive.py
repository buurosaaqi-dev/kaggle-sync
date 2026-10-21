#!/usr/bin/env python3
"""Authenticated, compressed OpenClaw state snapshots."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import struct
import tarfile
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


MAGIC = b"OCBK1\0\0\0"
ITERATIONS = 600_000
HEADER = struct.Struct(">8sI16s12s")
TAG_SIZE = 16
CHUNK_SIZE = 1024 * 1024
ROOT_NAMES = ("state", "home")


def derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    if not passphrase:
        raise ValueError("OPENCLAW_BACKUP_KEY is empty")
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    ).derive(passphrase.encode("utf-8"))


def sqlite_snapshot(source: Path, destination: Path) -> None:
    try:
        source_uri = f"file:{source.resolve().as_posix()}?mode=ro"
        with contextlib.closing(sqlite3.connect(source_uri, uri=True, timeout=30)) as src:
            if src.execute("PRAGMA schema_version").fetchone() is None:
                return
            temp = destination.with_suffix(destination.suffix + ".snapshot")
            with contextlib.closing(sqlite3.connect(temp)) as dst:
                src.backup(dst, pages=1024, sleep=0.01)
            os.replace(temp, destination)
    except sqlite3.Error:
        return


def make_snapshot(runtime_root: Path, snapshot_root: Path) -> None:
    for name in ROOT_NAMES:
        source = runtime_root / name
        target = snapshot_root / name
        if not source.exists():
            target.mkdir(parents=True, exist_ok=True)
            continue
        shutil.copytree(source, target, symlinks=True)
        for candidate in source.rglob("*"):
            if not candidate.is_file() or candidate.is_symlink():
                continue
            if candidate.suffix.lower() not in {".sqlite", ".sqlite3", ".db"}:
                continue
            sqlite_snapshot(candidate, target / candidate.relative_to(source))


def build_tar(runtime_root: Path, tar_path: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="openclaw-snapshot-") as temp_dir:
        snapshot_root = Path(temp_dir)
        make_snapshot(runtime_root, snapshot_root)
        with tarfile.open(tar_path, "w:gz", compresslevel=6) as archive:
            for name in ROOT_NAMES:
                archive.add(snapshot_root / name, arcname=name, recursive=True)


def encrypt_file(source: Path, destination: Path, passphrase: str) -> None:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    header = HEADER.pack(MAGIC, ITERATIONS, salt, nonce)
    key = derive_key(passphrase, salt, ITERATIONS)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(header)

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    try:
        with source.open("rb") as src, temporary.open("wb") as dst:
            dst.write(header)
            while chunk := src.read(CHUNK_SIZE):
                dst.write(encryptor.update(chunk))
            dst.write(encryptor.finalize())
            dst.write(encryptor.tag)
            dst.flush()
            os.fsync(dst.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def decrypt_file(source: Path, destination: Path, passphrase: str) -> None:
    total_size = source.stat().st_size
    if total_size < HEADER.size + TAG_SIZE:
        raise ValueError("backup is truncated")
    with source.open("rb") as src:
        header = src.read(HEADER.size)
        magic, iterations, salt, nonce = HEADER.unpack(header)
        if magic != MAGIC:
            raise ValueError("unsupported backup format")
        if not 100_000 <= iterations <= 5_000_000:
            raise ValueError("invalid PBKDF2 iteration count")
        src.seek(-TAG_SIZE, os.SEEK_END)
        tag = src.read(TAG_SIZE)
        ciphertext_size = total_size - HEADER.size - TAG_SIZE
        src.seek(HEADER.size)

        key = derive_key(passphrase, salt, iterations)
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(header)
        with destination.open("wb") as dst:
            remaining = ciphertext_size
            while remaining:
                chunk = src.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    raise ValueError("backup ciphertext is truncated")
                remaining -= len(chunk)
                dst.write(decryptor.update(chunk))
            try:
                dst.write(decryptor.finalize())
            except InvalidTag as exc:
                raise ValueError("backup authentication failed: wrong key or corrupt archive") from exc


def safe_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    accepted: list[tarfile.TarInfo] = []
    for member in archive.getmembers():
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise ValueError(f"unsafe archive path: {member.name}")
        if path.parts[0] not in ROOT_NAMES:
            raise ValueError(f"unexpected archive root: {member.name}")
        if member.isdev() or member.isfifo():
            raise ValueError(f"unsupported archive entry: {member.name}")
        if member.issym():
            target = PurePosixPath(member.linkname)
            resolved = path.parent.joinpath(target)
            if target.is_absolute() or ".." in resolved.parts:
                raise ValueError(f"unsafe symbolic link: {member.name}")
        if member.islnk():
            target = PurePosixPath(member.linkname)
            if target.is_absolute() or ".." in target.parts or target.parts[0] not in ROOT_NAMES:
                raise ValueError(f"unsafe hard link: {member.name}")
        accepted.append(member)
    return accepted


def merge_restore(extracted: Path, runtime_root: Path) -> None:
    runtime_root.mkdir(parents=True, exist_ok=True)
    for name in ROOT_NAMES:
        source = extracted / name
        destination = runtime_root / name
        if source.exists():
            shutil.copytree(source, destination, dirs_exist_ok=True, symlinks=True)
    for directory in (runtime_root / "state", runtime_root / "home"):
        if directory.exists():
            os.chmod(directory, 0o700)


def backup(runtime_root: Path, output: Path, passphrase: str) -> None:
    with tempfile.TemporaryDirectory(prefix="openclaw-backup-") as temp_dir:
        tar_path = Path(temp_dir) / "openclaw-state.tar.gz"
        build_tar(runtime_root, tar_path)
        encrypt_file(tar_path, output, passphrase)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    print(f"backup={output} bytes={output.stat().st_size} sha256={digest}")


def restore(runtime_root: Path, source: Path, passphrase: str) -> None:
    with tempfile.TemporaryDirectory(prefix="openclaw-restore-") as temp_dir:
        temp_root = Path(temp_dir)
        tar_path = temp_root / "openclaw-state.tar.gz"
        extracted = temp_root / "extracted"
        extracted.mkdir()
        decrypt_file(source, tar_path, passphrase)
        with tarfile.open(tar_path, "r:gz") as archive:
            members = safe_members(archive)
            archive.extractall(extracted, members=members)
        merge_restore(extracted, runtime_root)
    print(f"restored={source} runtime={runtime_root}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("backup", "restore"))
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--key-env", default="OPENCLAW_BACKUP_KEY")
    args = parser.parse_args()
    passphrase = os.environ.get(args.key_env, "")
    if args.operation == "backup":
        backup(args.runtime_root, args.archive, passphrase)
    else:
        restore(args.runtime_root, args.archive, passphrase)


if __name__ == "__main__":
    main()
