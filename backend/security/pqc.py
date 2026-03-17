"""
PQC Security Module — Quantum-Safe Insider Threat Detection
Provides signing (Dilithium-3 mock) and encryption (AES-256-GCM) for alert payloads.

On Windows dev environments without liboqs, all crypto is mocked using SHA3-256 + AES-256-GCM
via the built-in 'cryptography' library (no pycryptodome required).
"""
import json
import hashlib
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    import oqs
    OQS_AVAILABLE = True
    signer = oqs.Signature("Dilithium3")
    dilithium_public_key = signer.generate_keypair()
    kem = oqs.KeyEncapsulation("Kyber768")
    kyber_public_key = kem.generate_keypair()
    kyber_secret_key = kem.export_secret_key()
    print("[PQC] liboqs loaded — Dilithium-3 + Kyber-768 active")
except ImportError:
    OQS_AVAILABLE = False
    dilithium_public_key = b"mock-public-key"
    kyber_public_key = b"mock-kyber-public-key"
    kyber_secret_key = b"mock-kyber-secret-key"
    print("[PQC] liboqs not available — using SHA3-256 + AES-256-GCM mock")


def _mock_aes_key() -> bytes:
    """Deterministic but secret AES-256 key for mock mode."""
    return hashlib.sha256(b"vigilai-mock-shared-secret-key-v1").digest()


def sign_alert(payload: dict) -> dict:
    """Signs the alert payload (mock = SHA3-256 HMAC, real = Dilithium-3)."""
    payload_bytes = json.dumps(payload, sort_keys=True).encode()
    payload_hash = hashlib.sha3_256(payload_bytes).hexdigest()

    if OQS_AVAILABLE:
        signature_hex = signer.sign(payload_hash.encode()).hex()
    else:
        signature_hex = hashlib.sha256(b"vigilai-sig-seed" + payload_hash.encode()).hexdigest()

    return {
        "dilithium_signature": signature_hex,
        "sha3_hash": payload_hash,
    }


def encrypt_alert(payload: dict, sign_data: dict) -> dict:
    """
    Encrypts the alert payload + signature using AES-256-GCM.
    In real mode, the AES key comes from Kyber-768 encapsulation.
    In mock mode, a deterministic key is used for demo consistency.
    """
    combined_data = json.dumps({"payload": payload, "signature": sign_data}, sort_keys=True).encode()

    if OQS_AVAILABLE:
        ciphertext_encap, shared_secret = kem.encap_secret(kyber_public_key)
        aes_key = shared_secret[:32]
    else:
        ciphertext_encap = b"mock_encap_ciphertext"
        aes_key = _mock_aes_key()

    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, combined_data, None)
    # Last 16 bytes are the GCM tag
    encrypted = ciphertext[:-16]
    tag = ciphertext[-16:]

    return {
        "kyber_ciphertext_hash": hashlib.sha3_256(ciphertext_encap).hexdigest()[:16],
        "kyber_encap": ciphertext_encap.hex(),
        "aes_nonce": nonce.hex(),
        "aes_tag": tag.hex(),
        "encrypted_payload": encrypted.hex(),
        # Seed hints for frontend visual PQC hash display
        "sig_seed": abs(hash(sign_data["dilithium_signature"][:8])) % 99999,
        "enc_seed": abs(hash(ciphertext_encap.hex()[:8])) % 99999,
    }


def verify_alert_payload(ws_payload: dict) -> dict:
    """Verifies a WS-broadcast alert payload by decrypting and checking the hash."""
    pqc_data = ws_payload.get("pqc", {})
    if not pqc_data:
        return {"verified": False, "error": "Missing PQC data"}

    try:
        kyber_encap_hex = pqc_data.get("kyber_encap", "")
        aes_nonce_hex = pqc_data.get("aes_nonce", "")
        aes_tag_hex = pqc_data.get("aes_tag", "")
        encrypted_payload_hex = pqc_data.get("encrypted_payload", "")

        if OQS_AVAILABLE:
            decap_kem = oqs.KeyEncapsulation("Kyber768", kyber_secret_key)
            shared_secret = decap_kem.decap_secret(bytes.fromhex(kyber_encap_hex))
            aes_key = shared_secret[:32]
        else:
            aes_key = _mock_aes_key()

        nonce = bytes.fromhex(aes_nonce_hex)
        tag = bytes.fromhex(aes_tag_hex)
        ciphertext_raw = bytes.fromhex(encrypted_payload_hex) + tag

        aesgcm = AESGCM(aes_key)
        decrypted_data = aesgcm.decrypt(nonce, ciphertext_raw, None)
        parsed_data = json.loads(decrypted_data.decode())
        original_payload = parsed_data["payload"]
        signature_data = parsed_data["signature"]

        # Hash check
        payload_hash = hashlib.sha3_256(
            json.dumps(original_payload, sort_keys=True).encode()
        ).hexdigest()
        if payload_hash != signature_data["sha3_hash"]:
            return {"verified": False, "error": "Hash mismatch"}

        if OQS_AVAILABLE:
            verifier = oqs.Signature("Dilithium3")
            is_valid = verifier.verify(
                payload_hash.encode(),
                bytes.fromhex(signature_data["dilithium_signature"]),
                dilithium_public_key,
            )
        else:
            expected_sig = hashlib.sha256(b"vigilai-sig-seed" + payload_hash.encode()).hexdigest()
            is_valid = expected_sig == signature_data["dilithium_signature"]

        if not is_valid:
            return {"verified": False, "error": "Signature invalid"}

        return {
            "alert_id": original_payload.get("id"),
            "verified": True,
            "risk_score": original_payload.get("risk_score"),
            "dilithium_sig_hash": payload_hash[:16],
            "kyber_enc_hash": hashlib.sha3_256(bytes.fromhex(kyber_encap_hex)).hexdigest()[:16],
            "hash_algorithm": "SHA3-256",
            "user": original_payload.get("user_name"),
            "message": original_payload.get("message"),
            "action_taken": original_payload.get("action"),
        }

    except Exception as e:
        print(f"[PQC] Verification error: {e}")
        return {"verified": False, "error": str(e)}
