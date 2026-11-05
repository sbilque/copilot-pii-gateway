"""Generate the lab PKI: a test CA, the fake Copilot server certificate and the mitmproxy CA.

Test material only, written to the directory given as argument (a Docker volume in the lab).
"""
import datetime
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from mitmproxy.certs import CertStore

UPSTREAM_HOSTS = ['api.business.githubcopilot.com']


def name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'copilot-pii-gateway lab'),
                      x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def pem_key(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def main(out):
    out.mkdir(parents=True, exist_ok=True)
    if (out / 'lab-ca.pem').exists() and (out / 'mitmproxy-ca.pem').exists():
        print('PKI already present in', out)
        return
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(name('lab test CA')).issuer_name(name('lab test CA'))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                       content_commitment=False, key_encipherment=False, data_encipherment=False,
                                       key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(name(UPSTREAM_HOSTS[0])).issuer_name(ca.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(h) for h in UPSTREAM_HOSTS]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    (out / 'lab-ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (out / 'upstream.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM) + pem_key(key))
    CertStore.from_store(str(out), 'mitmproxy', 2048)
    print('PKI generated in', out)


main(Path(sys.argv[1] if len(sys.argv) > 1 else '/pki'))
