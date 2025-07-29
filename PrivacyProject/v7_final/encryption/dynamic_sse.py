import hmac
import hashlib
import base64

SSE_SECRET_KEY = b'253_secrete_23636123'   # 20 char only

def generate_search_token(keyword):

    token = hmac.new(SSE_SECRET_KEY, keyword.encode(), hashlib.sha256).digest()
    return base64.b64encode(token).decode()

def encrypt_keywords(keywords):

    tokens = []
    for kw in keywords:
        token = hmac.new(SSE_SECRET_KEY, kw.encode(), hashlib.sha256).digest()
        tokens.append(base64.b64encode(token).decode())
    return ",".join(tokens)

def search_in_keywords(encrypted_keywords, search_token):

    tokens = encrypted_keywords.split(',')
    return search_token in tokens
