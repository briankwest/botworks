# use for generating vapid keys for FireFox / Chrome Push Notifications
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import base64

# Generate a new ECDSA (P-256) key pair
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

# Export the public key in uncompressed format and base64 URL-encode it
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)
vapid_public_key = base64.urlsafe_b64encode(public_key_bytes).rstrip(b'=').decode('utf-8')

# Export the private key in DER format and base64 URL-encode it
private_key_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
vapid_private_key = base64.urlsafe_b64encode(private_key_bytes).rstrip(b'=').decode('utf-8')

print("VAPID Public Key:", vapid_public_key)
print("VAPID Private Key:", vapid_private_key)
