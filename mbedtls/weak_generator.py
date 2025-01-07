from ecdsa import SigningKey, SECP256k1, util
from hashlib import sha256
import hashlib
import random

N = 5

# Function to sign a message using ECDSA
def ecdsa_sign(message: str, private_key_int: int, i: int):
    """
    Sign a message using ECDSA with a private key and a weak random nonce.

    Args:
        message (str): The message to sign.
        private_key_int (int): The private key as an integer.

    Returns:
        dict: A dictionary containing the signature and the message.
    """
    # Convert the integer private key to bytes
    private_key_bytes = private_key_int.to_bytes(32, 'big')

    # Create a SigningKey object using SECP256k1 curve
    signing_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    
    # Get the corresponding public key in standard format starting with 04
    verifying_key = signing_key.verifying_key
    public_key = "04" + verifying_key.to_string().hex()

    # Generate a weak random nonce
    weak_nonce = i*1000

    # Sign the hashed message (non-deterministically)
    signature = signing_key.sign(
        message.encode('utf-8'),
        hashfunc=hashlib.sha256,
        k=weak_nonce,
        sigencode=util.sigencode_der
    )
    
    return {
        "message": message,
        "signature": signature.hex(),
        "public_key": public_key
    }

# Example usage
if __name__ == "__main__":
    private_key = 2
    f = open("../signatures/mock.txt", "w")
    for i in range(N):
        message = str(i)
        #print(message)
        result = ecdsa_sign(message, private_key, i+1)
        if(i == 0):
            print(result["public_key"].upper())
            f.write(result["public_key"].upper() + "\n")
        print(result["signature"].upper())
        f.write(result["signature"].upper() + "\n")
    f.close()