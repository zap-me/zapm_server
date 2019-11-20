import os
import binascii

def generate_key(num=20):
    return binascii.hexlify(os.urandom(num)).decode()
