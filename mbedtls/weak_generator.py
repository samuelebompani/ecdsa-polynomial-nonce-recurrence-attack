from ecdsa import SigningKey, SECP256k1, util, curves
import hashlib
import random

# Function to sign a message using ECDSA
def ecdsa_sign(message: str, private_key_int: int, i: int, k):
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
    weak_nonce = k[i-1]

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
    
def generate_weak_signatures(n):
    usedcurve = curves.SECP256k1
    #a = []
    #for i in range(n-2):
    #    a.append(random.randint(1, 10000))

    # # then, we generate the N nonces
    k = []
    # # the first one is random
    #k.append(random.randint(1, 10000))
    # # the other ones are computed with the recurrence equation
    #for i in range(n-1):
    #    new_k = 0
    #    for j in range(n-2):
    #        new_k += a[j]*(k[i]**j) % usedcurve.order
    #    k.append(new_k)
    for i in range(n):
        k.append(random.randint(1, 100000000000))
    
    private_key = 218782718271827182718
    #print(k)
    signatures = []
    hashes = []
    for i in range(n):
        message = str(i)
        hashes.append(int(hashlib.sha256(message.encode()).hexdigest(), 16))
        result = ecdsa_sign(message, private_key, i+1, k)
        if(i == 0):
            public_key = result["public_key"].upper()
        signatures.append(result["signature"].upper())
    return public_key, hashes, signatures