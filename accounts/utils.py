import base64
import binascii
import os
import json
from uuid import UUID
import hashlib

import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from django.core.files.uploadedfile import InMemoryUploadedFile


class JSONEncoder(json.JSONEncoder):
     def default(self, obj):
        if isinstance(obj, UUID):
            return str(obj)
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)

def generate_key():
    return binascii.hexlify(os.urandom(30)).decode()


def encode_base64(data):
    if isinstance(data, str):
        data = str.encode(data)
    return base64.b64encode(data)


def decode_base64(data):
    # print(data, type(data))
    return base64.b64decode(data)


def load_private_key(private_key):
    return serialization.load_pem_private_key(
        decode_base64(private_key),
        password=None,
        backend=default_backend()
    )


def load_public_key(public_key):
    return serialization.load_pem_public_key(
        decode_base64(public_key),
        backend=default_backend()
    )


def gen_keys():
    # return rsa.newkeys(512)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return encode_base64(public_pem), encode_base64(private_pem)


def encrypt(s, public_key):
    public_key = load_public_key(public_key)
    if isinstance(s, bytes):
        s = s.decode('utf-8')
    encrypted = public_key.encrypt(
        s,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return binascii.hexlify(encrypted)


def decrypt(s, private_key):
    s = binascii.unhexlify(s)
    private_key = load_private_key(private_key)
    original_message = private_key.decrypt(
        s,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return original_message


def to_md5(fname):
    hash_md5 = hashlib.md5()
    if isinstance(fname, str):
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
    if isinstance(fname, InMemoryUploadedFile):
        for chunk in fname.chunks(4096):# iter(lambda: fname.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

if __name__ == '__main__':
    pass
