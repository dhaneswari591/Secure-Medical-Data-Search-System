import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def derive_key(attributes: str, salt: bytes = b'static_salt_for_demo') -> bytes:

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(attributes.encode())

def abe_encrypt(data, attributes):
   
    key = derive_key(attributes)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data.encode(), None)
    encrypted = base64.b64encode(nonce + ct).decode()
    return encrypted

def abe_decrypt(ciphertext, user_attributes):
   
    try:
        key = derive_key(user_attributes)
        aesgcm = AESGCM(key)
        data = base64.b64decode(ciphertext)
        nonce = data[:12]
        ct = data[12:]
        decrypted_data = aesgcm.decrypt(nonce, ct, None)
        return decrypted_data.decode()
    except Exception:
        return None
