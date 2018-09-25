import os
import datetime
import pytz
import binascii
import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

def device_cert_sn(size, builder):
    pub_nums = builder._public_key.public_numbers()
    pubkey = pub_nums.x.to_bytes(32, byteorder='big', signed=False)
    pubkey += pub_nums.y.to_bytes(32, byteorder='big', signed=False)

    # Get the encoded dates
    expire_years = 0 
    enc_dates = bytearray(b'\x00'*3)
    enc_dates[0] = (enc_dates[0] & 0x07) | ((((builder._not_valid_before.year - 2000) & 0x1F) << 3) & 0xFF)
    enc_dates[0] = (enc_dates[0] & 0xF8) | ((((builder._not_valid_before.month) & 0x0F) >> 1) & 0xFF)
    enc_dates[1] = (enc_dates[1] & 0x7F) | ((((builder._not_valid_before.month) & 0x0F) << 7) & 0xFF)
    enc_dates[1] = (enc_dates[1] & 0x83) | (((builder._not_valid_before.day & 0x1F) << 2) & 0xFF)
    enc_dates[1] = (enc_dates[1] & 0xFC) | (((builder._not_valid_before.hour & 0x1F) >> 3) & 0xFF)
    enc_dates[2] = (enc_dates[2] & 0x1F) | (((builder._not_valid_before.hour & 0x1F) << 5) & 0xFF)
    enc_dates[2] = (enc_dates[2] & 0xE0) | ((expire_years & 0x1F) & 0xFF)
    enc_dates = bytes(enc_dates)

    # SAH256 hash of the public key and encoded dates
    digest = hashes.Hash(hashes.SHA256(), backend=crypto_be)
    digest.update(pubkey)
    digest.update(enc_dates)
    raw_sn = bytearray(digest.finalize()[:size])
    raw_sn[0] = raw_sn[0] & 0x7F # Force MSB bit to 0 to ensure positive integer
    raw_sn[0] = raw_sn[0] | 0x40 # Force next bit to 1 to ensure the integer won't be trimmed in ASN.1 DER encoding
    return int.from_bytes(raw_sn, byteorder='big', signed=False)

# backend
crypto_be = cryptography.hazmat.backends.default_backend()

print('Loading root CA certificate')
if not os.path.isfile('CARoot.crt'):
    raise Error('failed to load CARoot.crt')
with open('CARoot.crt', 'rb') as f:
    root_ca_cert = x509.load_pem_x509_certificate(f.read(), crypto_be)

print('Loading signer CA key')
if not os.path.isfile('signer.key'):
    raise Error('failed to load signer.key')
with open('signer.key', 'rb') as f:
    signer_ca_priv_key = serialization.load_pem_private_key(
      data=f.read(),
      password=None,
      backend=crypto_be)

print('Loading signer CA certificate')
if not os.path.isfile('signer.crt'):
    raise Error('failed to load signer.crt')
with open('signer.crt', 'rb') as f:
    signer_ca_cert = x509.load_pem_x509_certificate(f.read(), crypto_be)

print('Loading CertificationRequest from tbv.csr')
f = open('tbv.csr', 'r')

if not os.path.isfile('tbv.csr'):
    raise Error('failed to load tbv.csr')
with open('tbv.csr', 'rb') as f:
    device_csr = x509.load_der_x509_csr(f.read(), crypto_be)

if not device_csr.is_signature_valid:
    raise Error('device scr signature invalid')

print('Generating device certificate from CSR')
builder = x509.CertificateBuilder()
builder = builder.issuer_name(signer_ca_cert.subject)
builder = builder.not_valid_before(datetime.datetime.now(tz=pytz.utc).replace(minute=0,second=0))
builder = builder.not_valid_after(datetime.datetime(3000, 12, 31, 23, 59, 59))
builder = builder.subject_name(device_csr.subject)
builder = builder.public_key(device_csr.public_key())
builder = builder.serial_number(device_cert_sn(16, builder))

# add in extensions spedified by CSR
for extension in device_csr.extensions:
    builder = builder.add_extension(extension.value, extension.critical)

# Subject Key ID is used as the thing name and MQTT client ID and is required for this demo
builder = builder.add_extension(
    x509.SubjectKeyIdentifier.from_public_key(builder._public_key),
    critical=False)
issuer_ski = signer_ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
builder = builder.add_extension(
    x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski),
    critical=False)

# Sign certificate
device_cert = builder.sign(
    private_key=signer_ca_priv_key,
    algorithm=hashes.SHA256(),
    backend=crypto_be)

# find the subject key ID for use as the thing name
is_subject_key_id_found = False
for extension in device_cert.extensions:
    if extension.oid._name != 'subjectKeyIdentifier':
        continue
    print(binascii.b2a_hex(extension.value.digest).decode('ascii'))
    is_subject_key_id_found = True

if not is_subject_key_id_found:
    raise RuntimeError('could not find the subjectKeyIdentifier extension in the device certificate')

with open('device.crt', 'wb') as f:
    f.write(device_cert.public_bytes(encoding=serialization.Encoding.PEM))

print('----- END -----')







