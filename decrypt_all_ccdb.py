"""
decrypt_all_ccdb.py

Reads a local manifest 'file.json' in the current working directory,
finds all '.ccdb' files, and attempts to decrypt each using the hash
from the manifest. Decrypted outputs are written as '<name>.json'.

Usage:
    python decrypt_all_ccdb.py

Dependencies:
    pip install rncryptor

Ensure this script is run in the directory containing 'file.json' and the .ccdb files.
"""

import os
import json
import base64
import sys
from rncryptor import RNCryptor

def build_frt() -> str:
    # Reproduce Combo Cleaner Base.frt() sequence exactly
    ints = [
        115, 72, 119, 75, 85, 80, 52, 75, 90, 109, 78, 76, 104, 110, 67, 53,
        122, 122, 100, 113, 55, 97, 114, 89, 74, 71, 112, 50, 75, 55, 112, 51,
        116, 88, 51, 54, 70, 102, 101, 100, 84, 55, 110, 57, 74, 76, 90, 87,
        80, 107, 112, 90, 81, 112, 101, 122, 121, 66, 75, 112, 57, 54, 83, 54
    ]
    if len(ints) != 64:
        raise RuntimeError("Unexpected frt() length")
    return ''.join(chr(i) for i in ints)

def compute_key_from_hash(hash_str: str) -> str:
    idxs = [4, 14, 19, 23, 38, 41, 42, 55]
    if len(hash_str) <= max(idxs):
        raise ValueError(f"Hash string too short: {hash_str}")
    base = build_frt()
    suffix = ''.join(hash_str[i] for i in idxs)
    return base + suffix

def decrypt_rncryptor_base64(b64_content: str, password: str) -> bytes or str:
    try:
        encrypted_bytes = base64.b64decode(b64_content)
    except Exception as e:
        raise ValueError(f"Base64 decode failed: {e}")
    decryptor = RNCryptor()
    try:
        plaintext = decryptor.decrypt(encrypted_bytes, password)
    except Exception as e:
        raise ValueError(f"RNCryptor decryption failed: {e}")
    # Attempt to decode as UTF-8; if succeeds, return str, else return bytes
    try:
        return plaintext.decode('utf-8')
    except Exception:
        return plaintext

def load_manifest(manifest_path: str) -> dict:
    with open(manifest_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data

def find_entry(manifest: dict, filename: str) -> dict:
    # Manifest expected to have a list under "files" or similar
    files = manifest.get("files") or manifest.get("Files") or []
    for entry in files:
        name = entry.get("fileName") or entry.get("FileName") or entry.get("name")
        if name and name.lower() == filename.lower():
            return entry
    return None

def main():
    cwd = os.getcwd()
    manifest_file = os.path.join(cwd, 'files.json')
    if not os.path.isfile(manifest_file):
        print("Manifest 'file.json' not found in current directory.", file=sys.stderr)
        sys.exit(1)
    try:
        manifest = load_manifest(manifest_file)
    except Exception as e:
        print(f"Failed to load manifest: {e}", file=sys.stderr)
        sys.exit(1)

    ccdb_files = [f for f in os.listdir(cwd) if f.lower().endswith('.ccdb')]
    if not ccdb_files:
        print("No .ccdb files found in current directory.")
        return

    for ccdb in ccdb_files:
        print(f"Processing → {ccdb}")
        entry = find_entry(manifest, ccdb)
        if not entry:
            print(f"  ⚠️ No manifest entry for {ccdb}, skipping.")
            continue
        hash_str = entry.get("hash") or entry.get("Hash")
        if not hash_str:
            print(f"  ⚠️ No 'hash' field for {ccdb} in manifest, skipping.")
            continue
        # Read Base64 content
        try:
            with open(os.path.join(cwd, ccdb), 'r', encoding='utf-8') as f:
                b64_content = f.read().strip()
        except Exception as e:
            print(f"  ❌ Failed to read file: {e}")
            continue
        # Compute key and decrypt
        try:
            key = compute_key_from_hash(hash_str)
            plaintext = decrypt_rncryptor_base64(b64_content, key)
        except Exception as e:
            print(f"  ❌ Decryption failed: {e}")
            continue
        # Write output, handling str vs bytes
        out_name = os.path.splitext(ccdb)[0] + '.json'
        out_path = os.path.join(cwd, out_name)
        try:
            if isinstance(plaintext, str):
                with open(out_path, 'w', encoding='utf-8') as out_f:
                    out_f.write(plaintext)
            else:
                with open(out_path, 'wb') as out_f:
                    out_f.write(plaintext)
            print(f"  ✅ Decrypted to {out_name}")
        except Exception as e:
            print(f"  ❌ Failed to write decrypted output: {e}")

if __name__ == '__main__':
    main()
