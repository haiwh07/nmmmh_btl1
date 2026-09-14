from flask import Flask, render_template, request, jsonify, send_file
from io import BytesIO
from time import perf_counter
import base64, hashlib, struct

import numpy as np
from PIL import Image
from Crypto.Cipher import AES, DES3, Blowfish, ChaCha20
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

app = Flask(__name__)

MAGIC = b"WMK1"
MAX_TEXT = 100

# ---------- common helpers ----------

def key_bytes(key: str, n: int) -> bytes:
    return hashlib.sha256(key.encode("utf-8")).digest()[:n]

def pad(data, block):
    p = block - (len(data) % block)
    return data + bytes([p]) * p

def unpad(data, block):
    if not data or len(data) % block:
        raise ValueError("Dữ liệu padding không hợp lệ")
    p = data[-1]
    if p < 1 or p > block or data[-p:] != bytes([p]) * p:
        raise ValueError("Sai khóa hoặc dữ liệu bị hỏng")
    return data[:-p]

def timed_encrypt(name, text, key):
    t = perf_counter()
    blob = encrypt(name, text.encode("utf-8"), key)
    return blob, (perf_counter() - t) * 1000

def timed_decrypt(name, blob, key):
    t = perf_counter()
    plain = decrypt(name, blob, key)
    return plain.decode("utf-8"), (perf_counter() - t) * 1000

CURVE_ORDER_SECP256R1 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

def derive_recipient_key(key: str):
    """Deterministically derive the 'recipient' EC private key from the
    user's passphrase. Used on BOTH encrypt and decrypt so both sides land
    on the exact same static key pair; only the ephemeral key is random."""
    seed = int.from_bytes(hashlib.sha256(key.encode()).digest(), "big")
    seed = (seed % (CURVE_ORDER_SECP256R1 - 1)) + 1
    return ec.derive_private_key(seed, ec.SECP256R1())

# ---------- encryption algorithms ----------

def encrypt(name, data, key):
    if name == "AES":
        k = key_bytes(key, 32)
        nonce = get_random_bytes(12)
        cipher = AES.new(k, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(data)
        return nonce + tag + ct

    if name == "DES3":
        k = DES3.adjust_key_parity(key_bytes(key, 24))
        iv = get_random_bytes(8)
        cipher = DES3.new(k, DES3.MODE_CBC, iv)
        return iv + cipher.encrypt(pad(data, 8))

    if name == "Blowfish":
        k = key_bytes(key, 32)
        iv = get_random_bytes(8)
        cipher = Blowfish.new(k, Blowfish.MODE_CBC, iv)
        return iv + cipher.encrypt(pad(data, 8))

    if name == "ChaCha20":
        k = key_bytes(key, 32)
        nonce = get_random_bytes(8)
        cipher = ChaCha20.new(key=k, nonce=nonce)
        return nonce + cipher.encrypt(data)

    # Advanced 1: XChaCha20-Poly1305 through cryptography is not universally
    # available in all versions, so use AES-GCM as a modern AEAD baseline.
    # The UI labels this as AES-GCM advanced mode.
    if name == "AES-GCM-Advanced":
        k = key_bytes(key, 32)
        nonce = get_random_bytes(12)
        cipher = AES.new(k, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(data)
        return nonce + tag + ct

    # Advanced 2: ECIES-like hybrid using ephemeral ECDH + HKDF + AES-GCM.
    if name == "ECDH-AES-GCM":
        recipient = derive_recipient_key(key)
        eph = ec.generate_private_key(ec.SECP256R1())
        shared = eph.exchange(ec.ECDH(), recipient.public_key())
        aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                       info=b"watermark-ecdh").derive(shared)
        nonce = get_random_bytes(12)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(data)
        # This demonstration stores the ephemeral and recipient public keys
        # inside the blob so it remains self-contained.
        eph_pub = eph.public_key().public_bytes(
            encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.DER,
            format=__import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.SubjectPublicKeyInfo
        )
        rec_pub = recipient.public_key().public_bytes(
            encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.DER,
            format=__import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.SubjectPublicKeyInfo
        )
        return struct.pack(">H", len(eph_pub)) + eph_pub + struct.pack(">H", len(rec_pub)) + rec_pub + nonce + tag + ct

    raise ValueError("Thuật toán không được hỗ trợ")

def decrypt(name, blob, key):
    if name == "AES" or name == "AES-GCM-Advanced":
        if len(blob) < 28:
            raise ValueError("Ciphertext AES không hợp lệ")
        nonce, tag, ct = blob[:12], blob[12:28], blob[28:]
        cipher = AES.new(key_bytes(key, 32), AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ct, tag)

    if name == "DES3":
        iv, ct = blob[:8], blob[8:]
        cipher = DES3.new(DES3.adjust_key_parity(key_bytes(key, 24)), DES3.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), 8)

    if name == "Blowfish":
        iv, ct = blob[:8], blob[8:]
        cipher = Blowfish.new(key_bytes(key, 32), Blowfish.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), 8)

    if name == "ChaCha20":
        nonce, ct = blob[:8], blob[8:]
        cipher = ChaCha20.new(key=key_bytes(key, 32), nonce=nonce)
        return cipher.decrypt(ct)

    if name == "ECDH-AES-GCM":
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        pos = 0
        le = struct.unpack(">H", blob[pos:pos+2])[0]; pos += 2
        eph_pub = load_der_public_key(blob[pos:pos+le]); pos += le
        lr = struct.unpack(">H", blob[pos:pos+2])[0]; pos += 2
        rec_pub = load_der_public_key(blob[pos:pos+lr]); pos += lr
        # Reconstruct the deterministic recipient private key from the
        # passphrase (same derivation used in encrypt()). This is a demo
        # extension, not a production ECIES design.
        recipient = derive_recipient_key(key)
        shared = recipient.exchange(ec.ECDH(), eph_pub)
        aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                       info=b"watermark-ecdh").derive(shared)
        nonce, tag, ct = blob[pos:pos+12], blob[pos+12:pos+28], blob[pos+28:]
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ct, tag)

    raise ValueError("Thuật toán không được hỗ trợ")

# ---------- LSB ----------

def image_to_array(img):
    if img.mode != "RGB":
        img = img.convert("RGB")
    return np.array(img, dtype=np.uint8)

def psnr(a, b):
    a = a.astype(np.float64)
    b = b.astype(np.float64)
    mse = np.mean((a - b) ** 2)
    if mse == 0:
        return float("inf")
    return 10 * np.log10((255.0 ** 2) / mse)

def make_payload(algorithm, ciphertext):
    name = algorithm.encode("utf-8")
    return MAGIC + bytes([len(name)]) + name + struct.pack(">I", len(ciphertext)) + ciphertext

def embed(img, payload):
    arr = image_to_array(img).copy()
    raw = np.frombuffer(payload, dtype=np.uint8)
    bits = np.unpackbits(raw)
    capacity = arr.size
    if len(bits) > capacity:
        raise ValueError(f"Ảnh không đủ dung lượng. Cần {len(bits)} bit, có {capacity} bit.")
    flat = arr.reshape(-1)
    flat[:len(bits)] = (flat[:len(bits)] & 0xFE) | bits
    return Image.fromarray(arr)

def extract(img):
    arr = image_to_array(img)
    flat = arr.reshape(-1)
    first = np.array(flat[:40], dtype=np.uint8) & 1
    head = np.packbits(first).tobytes()
    if head[:4] != MAGIC:
        raise ValueError("Không tìm thấy watermark hợp lệ.")
    name_len = head[4]
    total_bits = (4 + 1 + name_len + 4) * 8
    bits = (np.array(flat[:total_bits], dtype=np.uint8) & 1)
    head_full = np.packbits(bits).tobytes()
    pos = 5
    name = head_full[pos:pos+name_len].decode("utf-8"); pos += name_len
    size = struct.unpack(">I", head_full[pos:pos+4])[0]; pos += 4
    data_bits = size * 8
    all_bits = (np.array(flat[:total_bits + data_bits], dtype=np.uint8) & 1)
    all_bytes = np.packbits(all_bits).tobytes()
    ciphertext = all_bytes[pos:pos+size]
    return name, ciphertext

# ---------- Flask routes ----------

ALGORITHMS = [
    "AES", "DES3", "Blowfish", "ChaCha20",
    "AES-GCM-Advanced", "ECDH-AES-GCM"
]

@app.get("/")
def index():
    return render_template("index.html", algorithms=ALGORITHMS)

@app.post("/api/embed")
def api_embed():
    try:
        image = request.files["image"]
        text = request.form["text"]
        key = request.form["key"]
        algorithm = request.form["algorithm"]

        if not text or len(text) > MAX_TEXT:
            raise ValueError("Watermark phải từ 1 đến 100 ký tự.")
        if algorithm not in ALGORITHMS:
            raise ValueError("Thuật toán không hợp lệ.")

        original = Image.open(image.stream).convert("RGB")
        ciphertext, enc_ms = timed_encrypt(algorithm, text, key)
        payload = make_payload(algorithm, ciphertext)

        out = embed(original, payload)
        score = psnr(image_to_array(original), image_to_array(out))

        buf = BytesIO()
        out.save(buf, format="PNG")
        buf.seek(0)

        return jsonify({
            "algorithm": algorithm,
            "psnr": None if score == float("inf") else round(float(score), 4),
            "encryption_ms": round(enc_ms, 4),
            "payload_bytes": len(payload),
            "image_base64": base64.b64encode(buf.getvalue()).decode()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.post("/api/extract")
def api_extract():
    try:
        image = Image.open(request.files["image"].stream).convert("RGB")
        selected = request.form["algorithm"]
        key = request.form["key"]
        embedded_algorithm, ciphertext = extract(image)

        if selected != embedded_algorithm:
            raise ValueError(f"Ảnh được nhúng bằng {embedded_algorithm}, nhưng bạn chọn {selected}.")

        text, dec_ms = timed_decrypt(selected, ciphertext, key)
        return jsonify({
            "algorithm": embedded_algorithm,
            "text": text,
            "decryption_ms": round(dec_ms, 4),
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.post("/api/benchmark")
def api_benchmark():
    try:
        text = request.form["text"]
        key = request.form["key"]
        results = []
        for name in ALGORITHMS:
            try:
                enc, enc_ms = timed_encrypt(name, text, key)
                _, dec_ms = timed_decrypt(name, enc, key)
                results.append({
                    "algorithm": name,
                    "encryption_ms": round(enc_ms, 4),
                    "decryption_ms": round(dec_ms, 4),
                    "ciphertext_bytes": len(enc)
                })
            except Exception as e:
                results.append({"algorithm": name, "error": str(e)})
        return jsonify({"results": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.post("/api/hash")
def api_hash():
    text = request.form["text"].encode("utf-8")
    return jsonify({
        "md5": hashlib.md5(text).hexdigest(),
        "sha256": hashlib.sha256(text).hexdigest()
    })

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)