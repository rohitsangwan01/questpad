import os
import sys
import time
import struct
import json
import ctypes
import ctypes.util

sys.path.insert(0, os.path.dirname(__file__))
from bridge import Bridge

# OpenSSL bindings for X25519 and AES-128-CCM
crypto = ctypes.CDLL(ctypes.util.find_library("crypto"))

NID_X25519 = 1034
EVP_CTRL_CCM_SET_IVLEN = 0x9
EVP_CTRL_CCM_SET_TAG = 0x11
EVP_CTRL_CCM_GET_TAG = 0x10

crypto.EVP_PKEY_new_raw_private_key.restype = ctypes.c_void_p
crypto.EVP_PKEY_new_raw_private_key.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
crypto.EVP_PKEY_new_raw_public_key.restype = ctypes.c_void_p
crypto.EVP_PKEY_new_raw_public_key.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
crypto.EVP_PKEY_get_raw_public_key.restype = ctypes.c_int
crypto.EVP_PKEY_get_raw_public_key.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t)]
crypto.EVP_PKEY_CTX_new.restype = ctypes.c_void_p
crypto.EVP_PKEY_CTX_new.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
crypto.EVP_PKEY_derive_init.restype = ctypes.c_int
crypto.EVP_PKEY_derive_init.argtypes = [ctypes.c_void_p]
crypto.EVP_PKEY_derive_set_peer.restype = ctypes.c_int
crypto.EVP_PKEY_derive_set_peer.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
crypto.EVP_PKEY_derive.restype = ctypes.c_int
crypto.EVP_PKEY_derive.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t)]
crypto.EVP_PKEY_free.argtypes = [ctypes.c_void_p]
crypto.EVP_PKEY_CTX_free.argtypes = [ctypes.c_void_p]

crypto.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
crypto.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
crypto.EVP_aes_128_ccm.restype = ctypes.c_void_p
crypto.EVP_CIPHER_CTX_ctrl.restype = ctypes.c_int
crypto.EVP_CIPHER_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
crypto.EVP_EncryptInit_ex.restype = ctypes.c_int
crypto.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
crypto.EVP_EncryptUpdate.restype = ctypes.c_int
crypto.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]
crypto.EVP_EncryptFinal_ex.restype = ctypes.c_int
crypto.EVP_EncryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]


def x25519_keygen():
    priv = os.urandom(32)
    pkey = crypto.EVP_PKEY_new_raw_private_key(NID_X25519, None, priv, 32)
    pub = ctypes.create_string_buffer(32)
    sz = ctypes.c_size_t(32)
    crypto.EVP_PKEY_get_raw_public_key(pkey, pub, ctypes.byref(sz))
    crypto.EVP_PKEY_free(pkey)
    return priv, bytes(pub.raw)


def x25519_derive(priv_bytes, peer_pub_bytes):
    priv_key = crypto.EVP_PKEY_new_raw_private_key(NID_X25519, None, priv_bytes, 32)
    peer_key = crypto.EVP_PKEY_new_raw_public_key(NID_X25519, None, peer_pub_bytes, 32)
    ctx = crypto.EVP_PKEY_CTX_new(priv_key, None)
    crypto.EVP_PKEY_derive_init(ctx)
    crypto.EVP_PKEY_derive_set_peer(ctx, peer_key)
    out = ctypes.create_string_buffer(32)
    sz = ctypes.c_size_t(32)
    crypto.EVP_PKEY_derive(ctx, out, ctypes.byref(sz))
    crypto.EVP_PKEY_CTX_free(ctx)
    crypto.EVP_PKEY_free(priv_key)
    crypto.EVP_PKEY_free(peer_key)
    return bytes(out.raw)


def aes_ccm_encrypt(key, iv_8, plaintext, aad=b"\x00", tag_len=4):
    nonce_13 = b"\x00" * 5 + iv_8
    ctx = crypto.EVP_CIPHER_CTX_new()
    cipher = crypto.EVP_aes_128_ccm()
    crypto.EVP_EncryptInit_ex(ctx, cipher, None, None, None)
    crypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, len(nonce_13), None)
    crypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag_len, None)
    crypto.EVP_EncryptInit_ex(ctx, None, None, key, nonce_13)
    out_len = ctypes.c_int(0)
    crypto.EVP_EncryptUpdate(ctx, None, ctypes.byref(out_len), None, len(plaintext))
    if aad:
        crypto.EVP_EncryptUpdate(ctx, None, ctypes.byref(out_len), aad, len(aad))
    ciphertext = ctypes.create_string_buffer(len(plaintext))
    crypto.EVP_EncryptUpdate(ctx, ciphertext, ctypes.byref(out_len), plaintext, len(plaintext))
    crypto.EVP_EncryptFinal_ex(ctx, None, ctypes.byref(out_len))
    tag = ctypes.create_string_buffer(tag_len)
    crypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, tag_len, tag)
    crypto.EVP_CIPHER_CTX_free(ctx)
    return bytes(ciphertext.raw) + bytes(tag.raw)


def pair_q3(b, network_id, link_key):
    print("Initiating Quest 3 ECDH pairing...")
    # Step 1: Generate Host X25519 keypair
    host_priv, host_pub = x25519_keygen()
    print(f"Host X25519 public key: {host_pub.hex()}")

    # Step 2: Send Command 0x12 (ecdh_public_key) with READ flag (read=True)
    # The payload is our 32-byte public key; controller returns its 32-byte public key
    print("Exchanging ECDH public keys (cmd 0x12, read=True)...")
    err, ctrl_pub = b.dm_cmd(0x12, payload=host_pub, read=True, timeout=3.0)
    if err or len(ctrl_pub) < 32:
        raise RuntimeError(f"ECDH public key exchange failed: err={err}, len={len(ctrl_pub)}, resp={ctrl_pub.hex() if ctrl_pub else 'empty'}")
    ctrl_pub = ctrl_pub[:32]
    print(f"Controller X25519 public key: {ctrl_pub.hex()}")

    # Step 3: Compute shared secret
    shared_secret = x25519_derive(host_priv, ctrl_pub)
    print(f"Shared secret: {shared_secret.hex()}")
    aes_key = shared_secret[:16]

    # Step 4: Encrypt pairing record with AES-128-CCM (20 bytes plain + 4 bytes MAC = 24 bytes)
    plaintext = struct.pack("<I", network_id) + link_key
    
    # Try with AAD = b"\x00" (Nordic S0 header) first, fallback to empty AAD if needed
    for aad in [b"\x00", b""]:
        iv_8 = os.urandom(8)
        ct_with_tag = aes_ccm_encrypt(aes_key, iv_8, plaintext, aad=aad, tag_len=4)
        payload = iv_8 + ct_with_tag  # 32 bytes (8B IV + 20B ciphertext + 4B MAC)
        print(f"Encrypted pairing payload ({len(payload)}B, aad={aad!r}): {payload.hex()}")

        # Step 5: Send Command 0x11 (ecdh_pairing without per-device key)
        # Using 0x11 ensures the controller stores our plaintext link_key (plaintext + 4) directly
        print("Writing encrypted pairing info (cmd 0x11, read=False)...")
        err, resp = b.dm_cmd(0x11, payload=payload, read=False, timeout=3.0)
        if not err:
            print("SUCCESS: Controller accepted encrypted pairing record via 0x11!")
            return True
        print(f"Command 0x11 rejected (err={err}, resp={resp.hex() if resp else 'empty'}), trying fallback Command 0x1D...")
        err, resp = b.dm_cmd(0x1D, payload=payload, read=False, timeout=3.0)
        if not err:
            print("SUCCESS: Controller accepted encrypted pairing record via 0x1D!")
            return True

    raise RuntimeError("Controller rejected encrypted pairing info with both 0x1D and 0x11")


def main():
    b = Bridge()
    print("dongle:", b.ping())
    b.dm_start(any_device=True)
    print("Waiting for controller in pairing mode (hold Oculus + B / Oculus + Y)...")
    connected, id0, id1 = b.dm_wait_link(timeout=120)
    print(f"Connected: id0={id0:#010x} id1={id1:#010x}")

    from dm import load_or_create_pairing, PAIRING_FILE, RESET
    p = load_or_create_pairing()
    net_id = p["network_id"]
    link_key = bytes.fromhex(p["link_key"])

    pair_q3(b, net_id, link_key)

    p["controllers"][f"{id0:08x}{id1:08x}"] = {"paired_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    json.dump(p, open(PAIRING_FILE, "w"), indent=2)
    print(f"Pairing stored in {PAIRING_FILE}: network {net_id:#010x}")

    try:
        b.dm_cmd(RESET)
    except Exception:
        pass
    print("Controller reset into main app")
    stored = b.pair_store(net_id, link_key)
    print("Pairing saved to dongle flash" if stored else "WARNING: Failed to save to dongle flash")
    b.link_resume()
    print("Hosting link resumed!")


if __name__ == "__main__":
    main()
