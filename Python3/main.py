from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

def decrypt(nonce, ciphertext, associated_data):
    key = "Your32Apiv3Key"

    key_bytes = str.encode(key)
    nonce_bytes = str.encode(nonce)
    ad_bytes = str.encode(associated_data)
    data = base64.b64decode(ciphertext)

    aesgcm = AESGCM(key_bytes)
    return aesgcm.decrypt(nonce_bytes, data, ad_bytes)
