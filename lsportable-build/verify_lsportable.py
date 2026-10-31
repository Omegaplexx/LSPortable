#!/usr/bin/env python3
"""Checks a finished lsportable file. Exits 1 and lists the problems if any check fails.

Usage:
    python3 verify_lsportable.py <lsportable>
"""
import struct
import sys
import zipfile

KEYSTORE_ENTRY = "assets/keystore"


def data_offset(f, info):
	f.seek(info.header_offset)
	header = f.read(30)
	if header[:4] != b"PK\x03\x04":
		return None
	name_len, extra_len = struct.unpack("<HH", header[26:30])
	return info.header_offset + 30 + name_len + extra_len


def check(path):
	problems = []
	with zipfile.ZipFile(path) as zf:
		bad = zf.testzip()
		if bad:
			problems.append(f"corrupt entry: {bad}")

		names = set(zf.namelist())
		for required in ("classes.dex", KEYSTORE_ENTRY):
			if required not in names:
				problems.append(f"missing entry: {required}")

		if KEYSTORE_ENTRY in names and zf.read(KEYSTORE_ENTRY)[:4] == b"\xfe\xed\xfe\xed":
			problems.append(f"{KEYSTORE_ENTRY} is a JKS file, it must be PKCS12")

		if "classes.dex" in names:
			info = zf.getinfo("classes.dex")
			if info.compress_type != zipfile.ZIP_STORED:
				problems.append("classes.dex is compressed, it must be stored")
			with open(path, "rb") as f:
				offset = data_offset(f, info)
			if offset is None:
				problems.append("classes.dex: bad local header")
			elif offset % 4:
				problems.append(f"classes.dex data starts at {offset}, not a multiple of 4")

			dex = zf.read("classes.dex")
			if not dex.startswith(b"dex\n"):
				problems.append("classes.dex has no dex magic")
			if b"LLSPortableEntry;" not in dex:
				problems.append("LSPortableEntry is not in classes.dex")
			# kotlin.Metadata is only an annotation and is harmless; anything else needs kotlin-stdlib
			stray = dex.replace(b"Lkotlin/Metadata;", b"").count(b"Lkotlin/")
			if stray:
				problems.append(f"{stray} reference(s) to kotlin classes, no stdlib on the classpath")

		for info in zf.infolist():
			if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
				problems.append(f"{info.filename}: unsupported compression {info.compress_type}")
	return problems


if __name__ == "__main__":
	if len(sys.argv) != 2:
		print(__doc__, file=sys.stderr)
		sys.exit(2)
	problems = check(sys.argv[1])
	if problems:
		print("lsportable check failed:", file=sys.stderr)
		for p in problems:
			print(f"  - {p}", file=sys.stderr)
		sys.exit(1)
	print("lsportable check passed")
