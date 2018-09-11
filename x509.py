import os
import binascii
import cryptography
from cryptography import x509

print("hello world")

f = open('tmpl.csr', 'r')
crypto_be = cryptography.hazmat.backends.default_backend()
csr = x509.load_der_x509_csr(f.read(), crypto_be)

print('public_key()', csr.public_key().public_numbers())
print('signature_algorithm_oid', csr.signature_algorithm_oid)
print('signature (hex)', binascii.b2a_hex(csr.signature))
print('is_signature_valid', csr.is_signature_valid)

