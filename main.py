#!/usr/bin/env python3
import json
import struct
import hashlib
import argparse
import urllib.request
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import dnfile

CONFIG_API_URL = "https://api.otherworld-legends.chillyroom.com/Configurator/Configurations"
ITUNES_LOOKUP_URL = "https://itunes.apple.com/lookup?bundleId=com.chillyroom.otherworld"

# Built-in AES-256 Key & IV extracted from game TextAssets
# (Resources/ejiowefj/mTxMvOMrphk, Resources/fioiufe/YVdhMWnO). Override with --key/--iv.
DEFAULT_KEY_HEX = "faa7678a6ed6ed9fed7c8b8e0e6a898359fd10f56052784b7826adb0492d21a9"
DEFAULT_IV_HEX = "54ff8147de331e2f144d2b06a4b407a2"

CHANNELS = {
    "ios": {
        "game_id": "com.chillyroom.otherworld",
        "distro_id": "68145419-5bb1-417d-84c4-bcdff2d9d106",
        "platform": "AppStore",
    },
    "gp": {
        "game_id": "com.chillyroom.zhmr.gp",
        "distro_id": "85508a6c-b6d3-4356-90c6-0cc7db5194e4",
        "platform": "GooglePlay",
    }
}


def get_latest_appstore_version() -> str:
    try:
        req = urllib.request.Request(ITUNES_LOOKUP_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            if data.get("resultCount", 0) > 0:
                return data["results"][0].get("version", "3.6.0")
    except Exception:
        pass
    return "3.6.0"


def fetch_hotfix_info(channel: str = "gp", version: str = None) -> dict:
    cfg = CHANNELS[channel]
    game_ver = version or (get_latest_appstore_version() if channel == "ios" else "3.6.0")
    headers = {
        "User-Agent": "UnityPlayer/2021.3.16f1",
        "x-game-id": cfg["game_id"],
        "x-distro-id": cfg["distro_id"],
        "x-game-version": game_ver,
        "x-delivery-platform": cfg["platform"],
        "x-game-lang": "en",
        "x-locale": "en",
        "Accept": "application/json"
    }
    req = urllib.request.Request(CONFIG_API_URL, headers=headers)
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode())

    raw_configs = data.get("configurations", "{}")
    configs = json.loads(raw_configs) if isinstance(raw_configs, str) else raw_configs
    hotfix = configs.get("Hotfix", {})
    file_list = hotfix.get("fileList", [])
    if not file_list:
        raise RuntimeError(f"No hotfix files returned for version {game_ver} ({channel}).")

    target = next((f for f in file_list if f.get("fileName") == "bpewsmdwurww"), file_list[0])
    return {
        "hotfixVersion": hotfix.get("hotfixVersion", "unknown"),
        "clientVersion": game_ver,
        "channel": channel,
        "fileName": target.get("fileName", "bpewsmdwurww"),
        "fileUrl": target.get("fileUrl"),
        "fileMd5": target.get("fileMd5"),
        "fileSize": target.get("fileSize")
    }


def download_hotfix(file_url: str, expected_md5: str = None) -> bytes:
    req = urllib.request.Request(file_url, headers={"User-Agent": "UnityPlayer/2021.3.16f1"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        content = resp.read()
    if expected_md5 and hashlib.md5(content).hexdigest().lower() != expected_md5.lower():
        raise ValueError("MD5 mismatch.")
    return content


def decrypt_gamelogic(raw_bytes: bytes, key: bytes, iv: bytes) -> bytes:
    if raw_bytes.startswith(b"MZ"):
        return raw_bytes
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(raw_bytes), AES.block_size)
    if not decrypted.startswith(b"MZ"):
        raise ValueError("Decrypted output invalid - wrong Key/IV.")
    return decrypted


def _parse_constant(elem_type: int, raw_bytes: bytes):
    if not raw_bytes:
        return None
    try:
        if elem_type in (0x08, 0x09) and len(raw_bytes) >= 4:
            return struct.unpack("<i" if elem_type == 0x08 else "<I", raw_bytes[:4])[0]
        if elem_type in (0x04, 0x05) and len(raw_bytes) >= 1:
            return raw_bytes[0]
        if elem_type in (0x06, 0x07) and len(raw_bytes) >= 2:
            return struct.unpack("<h" if elem_type == 0x06 else "<H", raw_bytes[:2])[0]
        if elem_type in (0x0A, 0x0B) and len(raw_bytes) >= 8:
            return struct.unpack("<q" if elem_type == 0x0A else "<Q", raw_bytes[:8])[0]
        if elem_type == 0x02:
            return bool(raw_bytes[0])
        if elem_type == 0x0E:
            return raw_bytes.decode("utf-16le", errors="ignore")
        return raw_bytes.hex()
    except Exception:
        return None


def parse_gamelogic_dll(dll_path: str, output_file: str = "owl_data.json") -> dict:
    """Dumps every enum in the DLL as raw {id, name} pairs. No whitelist, no
    hero/boss/monster guessing, no derived pretty names - just what's there."""
    dn = dnfile.dnPE(dll_path)

    field_const_by_idx = {}
    if dn.net.mdtables.Constant:
        for c in dn.net.mdtables.Constant:
            if c.Parent and type(c.Parent.row).__name__ == "FieldRow":
                field_const_by_idx[c.Parent.row_index] = (c.Type, c.Value.value if c.Value else b"")

    all_enums = {}
    for row in dn.net.mdtables.TypeDef:
        extends = getattr(row, "Extends", None)
        if not (extends and hasattr(extends, "row") and extends.row):
            continue
        if getattr(extends.row, "TypeName", "") != "Enum":
            continue

        ename = str(row.TypeName)
        members = []
        for f_idx in row.FieldList:
            fname = str(f_idx.row.Name)
            if fname == "value__":
                continue
            c_info = field_const_by_idx.get(f_idx.row_index)
            val = _parse_constant(c_info[0], c_info[1]) if c_info else None
            members.append({"id": val, "name": fname})
        if members:
            all_enums[ename] = members

    results = {
        "total_enums": len(all_enums),
        "total_entries": sum(len(v) for v in all_enums.values()),
        "enums": all_enums
    }

    if output_file:
        out_path = Path(output_file)
        if out_path.parent:
            out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
    return results


def main():
    parser = argparse.ArgumentParser(description="Fetch hotfix, decrypt GameLogic.dll, parse every enum raw")
    parser.add_argument("--channel", choices=["ios", "gp"], default="gp", help="gp=Android Google Play, ios=iOS AppStore")
    parser.add_argument("--version", type=str, default=None)
    parser.add_argument("--key", type=str, default=None, help="AES key in hex (or raw string), overrides built-in default")
    parser.add_argument("--iv", type=str, default=None, help="AES IV in hex (or raw string), overrides built-in default")
    parser.add_argument("--dll", type=str, default=None, help="Skip fetch/decrypt, parse an already-decrypted GameLogic.dll directly")
    parser.add_argument("--output", type=str, default="owl_data.json", help="Path to output json file")
    parser.add_argument("--output-dir", type=str, default="./owl_dump")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.dll:
        data = parse_gamelogic_dll(args.dll, args.output)
        print(f"[+] Parsed {data['total_enums']} enums / {data['total_entries']} entries -> {args.output}")
        return

    info = fetch_hotfix_info(args.channel, args.version)
    print(f"[+] Found hotfix: {info['fileUrl']}")
    downloaded = download_hotfix(info["fileUrl"], info["fileMd5"])

    key_bytes = bytes.fromhex(args.key) if args.key and len(args.key) in (32, 48, 64) else (args.key.encode() if args.key else None)
    iv_bytes = bytes.fromhex(args.iv) if args.iv and len(args.iv) == 32 else (args.iv.encode() if args.iv else None)

    if not key_bytes or not iv_bytes:
        key_bytes = bytes.fromhex(DEFAULT_KEY_HEX)
        iv_bytes = bytes.fromhex(DEFAULT_IV_HEX)
        print(f"[+] Using built-in default AES Key & IV ({len(key_bytes)}B / {len(iv_bytes)}B)")

    dll_bytes = decrypt_gamelogic(downloaded, key_bytes, iv_bytes)
    dll_path = out_dir / "GameLogic.dll"
    with open(dll_path, "wb") as f:
        f.write(dll_bytes)

    data = parse_gamelogic_dll(str(dll_path), args.output)
    print(f"[+] Parsed {data['total_enums']} enums / {data['total_entries']} entries -> {args.output}")


if __name__ == "__main__":
    main()