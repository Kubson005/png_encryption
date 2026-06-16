from math import gcd
from pathlib import Path
from sympy import randprime
import zlib

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

def read_png_bytes(path: Path) -> bytes:
    data = path.read_bytes()
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("niepoprawny format PNG")
    return data

def generate_rsa_key():
    p = randprime(10**5, 10**6)
    q = randprime(10**5, 10**6)
    while q == p:
        q = randprime(10**5, 10**6)

    n = p * q
    fi = (p - 1) * (q - 1)
    e = 65537
    # gcd - największy wspólny dzielnik
    if not (1 < e < fi) or gcd(e, fi) != 1:
        e = next(candidate for candidate in range(3, fi, 2) if gcd(candidate, fi) == 1)

    d = pow(e, -1, fi)
    assert (d * e) % fi == 1

    public_key = (n, e)
    private_key = (n, d)
    return public_key, private_key

def encode_png(photo):
    if isinstance(photo, (bytes, bytearray)):
        data = bytes(photo)
        out_path = None
    else:
        path = Path(photo)
        data = read_png_bytes(path)
        out_path = path.with_name(path.stem + "_enc.png")

    public_key, private_key = generate_rsa_key()
    n, e = public_key

    def rsa_encrypt_bytes(plain: bytes) -> bytes:
        k = (n.bit_length() + 7) // 8
        out = bytearray()
        for b in plain:
            c = pow(b, e, n)
            out.extend(c.to_bytes(k, "big"))
        return bytes(out)

    # zachowaj sygnaturę
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("niepoprawny format PNG")

    out = bytearray()
    out.extend(PNG_SIGNATURE)

    offset = len(PNG_SIGNATURE)
    length = len(data)

    while offset < length:
        if offset + 8 > length:
            break
        chunk_len = int.from_bytes(data[offset:offset+4], "big")
        chunk_type = data[offset+4:offset+8]
        chunk_data = data[offset+8: offset+8+chunk_len]
        chunk_crc = data[offset+8+chunk_len: offset+12+chunk_len]

        if chunk_type == b"IDAT":
            new_chunk_data = rsa_encrypt_bytes(chunk_data)
            new_len = len(new_chunk_data)
            new_crc = zlib.crc32(chunk_type + new_chunk_data) & 0xFFFFFFFF
            out.extend(new_len.to_bytes(4, "big"))
            out.extend(chunk_type)
            out.extend(new_chunk_data)
            out.extend(new_crc.to_bytes(4, "big"))
        else:
            # pozostaw niezmienione
            out.extend(chunk_len.to_bytes(4, "big"))
            out.extend(chunk_type)
            out.extend(chunk_data)
            out.extend(chunk_crc)

        offset += 12 + chunk_len

    result = bytes(out)
    if out_path:
        out_path.write_bytes(result)
        return out_path
    return result

if __name__ == "__main__":
    source = Path("shark.png")
    png_bytes = read_png_bytes(source)
    print(encode_png(png_bytes))
