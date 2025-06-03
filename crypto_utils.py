from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib

# ==== VIGENERE ====
def vigenere_encrypt(text, key):
    result = ''
    key = key.upper()
    key_index = 0

    for char in text:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            k = ord(key[key_index % len(key)]) - 65
            result += chr((ord(char) - offset + k) % 26 + offset)
            key_index += 1
        else:
            result += char
    return result

def vigenere_decrypt(cipher, key):
    result = ''
    key = key.upper()
    key_index = 0

    for char in cipher:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            k = ord(key[key_index % len(key)]) - 65
            result += chr((ord(char) - offset - k) % 26 + offset)
            key_index += 1
        else:
            result += char
    return result

# ==== AES ====
def aes_encrypt(data, key):
    key_bytes = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode()
    ct = base64.b64encode(ct_bytes).decode()
    return f"{iv}:{ct}"

def aes_decrypt(ciphertext, key):
    key_bytes = hashlib.sha256(key.encode()).digest()
    iv, ct = ciphertext.split(':')
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()
