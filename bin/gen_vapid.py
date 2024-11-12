from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import base64

# Generate the private key
private_key = ec.generate_private_key(ec.SECP256R1())

# Get the public key
public_key = private_key.public_key()

# Serialize the private key
private_numbers = private_key.private_numbers()
private_value = private_numbers.private_value.to_bytes(32, byteorder='big')

# Serialize the public key
public_numbers = public_key.public_numbers()
x = public_numbers.x.to_bytes(32, byteorder='big')
y = public_numbers.y.to_bytes(32, byteorder='big')
public_value = b'\x04' + x + y  # Uncompressed point format

# Base64 URL-encode the keys without padding
def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

print('Public Key:', b64url_encode(public_value))
print('Private Key:', b64url_encode(private_value))
