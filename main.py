"""
Szyfrowanie i deszyfracja pliku PNG algorytmem RSA (wymagania.md).

Wymaga pliku `earthrise.png` w katalogu. Obrazy są tylko WYŚWIETLANE podczas
uruchomienia (nie zapisywane na dysk). Para kluczy RSA jest wpisana na sztywno
(projekt pokazowy, mały klucz dla szybkości).

Realizacja wymagań:
  1. Szyfrowanie i deszyfracja PNG algorytmem RSA (round-trip weryfikowany).
  2. Szyfrowana jest tylko masa bitowa (IDAT); reszta chunków oryginału jest
     zachowana w prywatnym chunku 'rsameta' i odtwarzana przy deszyfracji.
     RSA powiększa dane (1 bajt -> k bajtów), więc plik zaszyfrowany jest nowym,
     poprawnym PNG w skali szarości o wymiarach dobranych do szyfrogramu — to
     jedyna (uzasadniona) zmiana metadanych.
  3. Metoda A: dekompresja IDAT -> szyfrowanie -> kompresja. Metoda B:
     bezpośrednie szyfrowanie skompresowanego IDAT. (porównanie równoważności)
  4. RSA oraz tryby ECB/CBC zaimplementowane samodzielnie (bez bibliotek krypto).
  5. Dwa tryby: ECB oraz CBC.
  6. Podglądy ECB vs CBC wyświetlane do oceny czytelności (zarys obiektu).
  7. Porównanie z gotowym RSA (pycryptodome) na tej samej parze kluczy.
  8. Omówienie różnic wypisywane na konsolę.
"""

from __future__ import annotations

import io
import json
import secrets
import zlib
from pathlib import Path

import numpy as np
from PIL import Image, PngImagePlugin

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

# --------------------------------------------------------------------------- #
# 4. Klucz RSA — na sztywno (projekt pokazowy).
#     Para wygenerowana raz; n ~256 bitów (k = 32 B). Mały i szybki, ale:
#     - n musi być > 255, bo szyfrujemy bajt po bajcie (odwracalność),
#     - musi wystarczyć na padding biblioteki w porównaniu (wym. 7).
# --------------------------------------------------------------------------- #

KEYS = {
    "n": 106388111834322949854425353383396711311683384257552734045390662238205347136311,
    "e": 65537,
    "d": 32051007523336013578982470622728911425988322747235372281433940819503627489537,
}


def k_len(n: int) -> int:
    return (n.bit_length() + 7) // 8


# --------------------------------------------------------------------------- #
# 5. Tryby ECB i CBC (własne). Jednostka jawna = 1 bajt, szyfrogram = k bajtów.
# --------------------------------------------------------------------------- #

def ecb_encrypt(data: bytes, n: int, e: int) -> bytes:
    k = k_len(n)
    return b"".join(pow(b, e, n).to_bytes(k, "big") for b in data)


def ecb_decrypt(cipher: bytes, n: int, d: int) -> bytes:
    k = k_len(n)
    return bytes(pow(int.from_bytes(cipher[i:i + k], "big"), d, n) & 0xFF
                 for i in range(0, len(cipher), k))


def _fold(block: bytes, index: int) -> int:
    """Sprzężenie CBC: XOR całego bloku szyfrogramu z numerem bloku
    (mieszanie całego bloku + pozycji usuwa cykle w jednolitych obszarach)."""
    fb = index & 0xFF
    for byte in block:
        fb ^= byte
    return fb


def cbc_encrypt(data: bytes, n: int, e: int, iv: int) -> bytes:
    k = k_len(n)
    out, fb = bytearray(), iv & 0xFF
    for i, b in enumerate(data):
        block = pow(b ^ fb, e, n).to_bytes(k, "big")
        out.extend(block)
        fb = _fold(block, i)
    return bytes(out)


def cbc_decrypt(cipher: bytes, n: int, d: int, iv: int) -> bytes:
    k = k_len(n)
    out, fb = bytearray(), iv & 0xFF
    for i, off in enumerate(range(0, len(cipher), k)):
        block = cipher[off:off + k]
        x = pow(int.from_bytes(block, "big"), d, n)
        out.append((x ^ fb) & 0xFF)
        fb = _fold(block, i)
    return bytes(out)


def encrypt_stream(data: bytes, mode: str, keys: dict, iv: int) -> bytes:
    if mode == "ecb":
        return ecb_encrypt(data, keys["n"], keys["e"])
    return cbc_encrypt(data, keys["n"], keys["e"], iv)


def decrypt_stream(cipher: bytes, mode: str, keys: dict, iv: int) -> bytes:
    if mode == "ecb":
        return ecb_decrypt(cipher, keys["n"], keys["d"])
    return cbc_decrypt(cipher, keys["n"], keys["d"], iv)


# --------------------------------------------------------------------------- #
# 2./3. Obsługa PNG: chunki, wydzielenie IDAT, opakowanie szyfrogramu
# --------------------------------------------------------------------------- #

def parse_chunks(data: bytes) -> list[tuple[str, bytes]]:
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("niepoprawny format PNG")
    chunks, off = [], len(PNG_SIGNATURE)
    while off + 8 <= len(data):
        length = int.from_bytes(data[off:off + 4], "big")
        ctype = data[off + 4:off + 8].decode("latin-1")
        chunks.append((ctype, data[off + 8:off + 8 + length]))
        off += 12 + length
        if ctype == "IEND":
            break
    return chunks


def assemble_png(chunks: list[tuple[str, bytes]]) -> bytes:
    out = bytearray(PNG_SIGNATURE)
    for ctype, cdata in chunks:
        tb = ctype.encode("latin-1")
        crc = zlib.crc32(tb + cdata) & 0xFFFFFFFF
        out += len(cdata).to_bytes(4, "big") + tb + cdata + crc.to_bytes(4, "big")
    return bytes(out)


def extract_idat(chunks: list[tuple[str, bytes]]) -> tuple[bytes, int]:
    idat, first = bytearray(), None
    for i, (ctype, cdata) in enumerate(chunks):
        if ctype == "IDAT":
            first = i if first is None else first
            idat += cdata
    if first is None:
        raise ValueError("brak IDAT")
    return bytes(idat), first


def wrap_cipher_as_png(cipher: bytes, meta: dict) -> bytes:
    """Pakuje szyfrogram w poprawny, otwieralny PNG (grayscale) + metadane."""
    width = 1024
    height = max(1, (len(cipher) + width - 1) // width)
    padded = cipher + b"\x00" * (width * height - len(cipher))
    img = Image.fromarray(np.frombuffer(padded, np.uint8).reshape(height, width), "L")
    info = PngImagePlugin.PngInfo()
    info.add_text("rsameta", json.dumps(meta), zip=True)
    buf = io.BytesIO()
    img.save(buf, "PNG", pnginfo=info)
    return buf.getvalue()


# --------------------------------------------------------------------------- #
# 1./3. Szyfrowanie i deszyfracja PNG (metody A i B), w pamięci
# --------------------------------------------------------------------------- #

def encrypt_png(png_bytes: bytes, mode: str, method: str, keys: dict) -> bytes:
    chunks = parse_chunks(png_bytes)
    idat, idat_index = extract_idat(chunks)
    plain = zlib.decompress(idat) if method == "A" else idat

    iv = secrets.randbelow(256)
    cipher = encrypt_stream(plain, mode, keys, iv)
    meta = {
        "method": method, "mode": mode, "iv": iv, "k": k_len(keys["n"]),
        "n_plain": len(plain), "idat_index": idat_index,
        "other_chunks": [(t, d.hex()) for t, d in chunks if t != "IDAT"],
    }
    return wrap_cipher_as_png(cipher, meta)


def decrypt_png(enc_bytes: bytes, keys: dict) -> bytes:
    img = Image.open(io.BytesIO(enc_bytes))
    img.load()
    meta = json.loads(img.text["rsameta"])
    cipher = np.asarray(img, np.uint8).tobytes()[: meta["n_plain"] * meta["k"]]

    plain = decrypt_stream(cipher, meta["mode"], keys, meta["iv"])
    idat = zlib.compress(plain) if meta["method"] == "A" else plain

    rebuilt, inserted = [], False
    for i, (t, hx) in enumerate(meta["other_chunks"]):
        if i == meta["idat_index"]:
            rebuilt.append(("IDAT", idat))
            inserted = True
        rebuilt.append((t, bytes.fromhex(hx)))
    if not inserted:
        pos = next((j for j, (t, _) in enumerate(rebuilt) if t == "IEND"), len(rebuilt))
        rebuilt.insert(pos, ("IDAT", idat))
    return assemble_png(rebuilt)


# --------------------------------------------------------------------------- #
# 6. Podgląd do oceny czytelności (zachowuje wymiary oryginału)
# --------------------------------------------------------------------------- #

def make_preview(png_bytes: bytes, mode: str, keys: dict) -> Image.Image:
    img = Image.open(io.BytesIO(png_bytes))
    img.load()
    arr = np.asarray(img, np.uint8)
    cipher = encrypt_stream(arr.tobytes(), mode, keys, secrets.randbelow(256))
    k = k_len(keys["n"])
    low = bytes(cipher[i] for i in range(k - 1, len(cipher), k))  # młodszy bajt bloku
    return Image.fromarray(np.frombuffer(low, np.uint8).reshape(arr.shape), img.mode)


# --------------------------------------------------------------------------- #
# 7./8. Porównanie z gotową biblioteką RSA na tej samej parze kluczy
# --------------------------------------------------------------------------- #

def compare_with_library(keys: dict = KEYS) -> None:
    from Crypto.Cipher import PKCS1_v1_5
    from Crypto.PublicKey import RSA

    n, e, d = keys["n"], keys["e"], keys["d"]
    sample = b"ABCABCABCABCABC"
    k = k_len(n)

    our = ecb_encrypt(sample, n, e)
    first = our[:k]
    repeats = sum(our[i:i + k] == first for i in range(0, len(our), k))

    lib = PKCS1_v1_5.new(RSA.construct((n, e, d)))
    c1, c2 = lib.encrypt(sample), lib.encrypt(sample)

    print(f"Klucz: n={n.bit_length()} bitów, k={k} B, e={e}")
    print(f"Nasz ECB: {len(our)} B; identycznych bloków jak 'A': {repeats} (determinizm)")
    print(f"pycryptodome PKCS#1 v1.5: {len(c1)} B; dwa szyfrowania różne: {c1 != c2} "
          f"(losowy padding); deszyfracja OK: {lib.decrypt(c1, None) == sample}")
    print("Wniosek: biblioteczny RSA z paddingiem jest niedeterministyczny i nie "
          "ujawnia wzorców; nasz textbook-RSA w ECB jest deterministyczny, więc widać "
          "zarys obiektu, a CBC ten zarys ukrywa.")


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #

def images_equal(a: bytes, b: bytes) -> bool:
    ia = np.asarray(Image.open(io.BytesIO(a)).convert("RGBA"))
    ib = np.asarray(Image.open(io.BytesIO(b)).convert("RGBA"))
    return ia.shape == ib.shape and bool((ia == ib).all())


def show_gallery(items: list[tuple[str, Image.Image]]) -> None:
    """Wyświetla wszystkie obrazy w jednym oknie, każdy z podpisem."""
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, len(items), figsize=(4 * len(items), 4))
    if len(items) == 1:
        axes = [axes]
    for ax, (title, img) in zip(axes, items):
        ax.imshow(img, cmap="gray" if img.mode == "L" else None)
        ax.set_title(title, fontsize=10)
        ax.axis("off")
    fig.suptitle("Szyfrowanie PNG algorytmem RSA", fontsize=13)
    fig.tight_layout()
    plt.show()


def main() -> None:
    source = Path("earthrise.png")
    if not source.exists():
        raise SystemExit("Brak pliku earthrise.png w katalogu.")
    original = source.read_bytes()
    keys = KEYS
    print(f"Klucz RSA: n={keys['n'].bit_length()} bitów, k={k_len(keys['n'])} B\n")

    print("=== Szyfrowanie + deszyfracja + round-trip (wym. 1-3, 5) ===")
    for method in ("A", "B"):
        for mode in ("ecb", "cbc"):
            enc = encrypt_png(original, mode, method, keys)
            dec = decrypt_png(enc, keys)
            print(f"  metoda {method} / {mode.upper()}: round-trip OK = "
                  f"{images_equal(original, dec)} (szyfrogram {len(enc)} B)")

    print("\n=== Porównanie z gotową biblioteką RSA (wym. 7-8) ===")
    compare_with_library(keys)

    print("\n=== Wyświetlam podpisane obrazy (wym. 2, 6) ===")
    enc_png = encrypt_png(original, "ecb", "A", keys)
    show_gallery([
        ("Oryginał", Image.open(io.BytesIO(original))),
        ("Plik zaszyfrowany\n(poprawny PNG, grayscale)", Image.open(io.BytesIO(enc_png))),
        ("Podgląd ECB\n(widoczny zarys)", make_preview(original, "ecb", keys)),
        ("Podgląd CBC\n(szum)", make_preview(original, "cbc", keys)),
        ("Po deszyfracji", Image.open(io.BytesIO(decrypt_png(enc_png, keys)))),
    ])


if __name__ == "__main__":
    main()
