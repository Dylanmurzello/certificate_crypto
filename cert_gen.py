from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address

# Generate a private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=3072,
    backend=default_backend()
)

# Define the subject
subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u'usca.edu')
])

# Define the validity period
validity_period = timedelta(days=365)

# Define the subject alternative names
san = [
    x509.DNSName(u'www.usca.edu'),
    x509.IPAddress(IPv6Address(u'2606:4700:10::6816:268a')),
    x509.IPAddress(IPv6Address(u'2606:4700:10::6816:278a')),
    x509.IPAddress(IPv6Address(u'2606:4700:10::ac43:2686')),
    x509.IPAddress(IPv4Address(u'172.67.38.134')),
    x509.IPAddress(IPv4Address(u'104.22.38.138')),
    x509.IPAddress(IPv4Address(u'104.22.39.138'))
]

# Create the certificate
certificate = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(subject)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + validity_period)
    .add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False,
    )
    .add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
        critical=False,
    )
    .add_extension(
        x509.KeyUsage(
            digital_signature=True, key_encipherment=True, content_commitment=True,
            data_encipherment=False, key_agreement=False, encipher_only=False,
            decipher_only=False, key_cert_sign=False, crl_sign=False
        ),
        critical=True,
    )
    .add_extension(
        x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
        critical=False,
    )
    .add_extension(
        x509.SubjectAlternativeName(san),
        critical=False,
    )
    .sign(private_key, hashes.SHA384(), default_backend())
)

# Write the certificate to a file
with open("public_cert.pem", "wb") as f:
    f.write(certificate.public_bytes(Encoding.PEM))
