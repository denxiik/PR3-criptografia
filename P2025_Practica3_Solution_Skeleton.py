import random
import hashlib
from sympy import isprime, mod_inverse

def generate_prime_candidate(length):
    """
    Generates a random prime value of a given length.
    """
    p = random.getrandbits(length)
    while not isprime(p):
        p = random.getrandbits(length)
    return p

def mcd(a, b):
    """
    Calculates the greatest common divisor (GCD) of two numbers using the Euclidean algorithm.
    """
    while b:
        a, b = b, a % b
    return a

def generate_keypair(length):
    """
    Generates an RSA key pair (public and private).
    """
    p = generate_prime_candidate(length // 2)
    q = generate_prime_candidate(length // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = random.randrange(1, phi)
    while mcd(e, phi) != 1:
        e = random.randrange(1, phi)

    d = mod_inverse(e, phi)
    
    return ((e, n), (d, n))

def encrypt(Kpub, m):
    """
    Encrypts a message using the RSA public key.
    """
    e, n = Kpub
    cipher = pow(m, e, n)
    return cipher

def decrypt(Kpriv, ciphertext):
    """
    Decrypts a ciphertext using the RSA private key.
    """
    d, n = Kpriv
    plain = pow(ciphertext, d, n)
    return plain

def sign(Kpriv, message):
    """
    Digitally signs a message using the RSA private key.
    """
    d, n = Kpriv
    signature = pow(message, d, n)
    return signature

def verify(Kpub, message, signature):
    """
    Verifies an RSA digital signature using the public key.
    """
    e, n = Kpub
    decrypted_signature = pow(signature, e, n)
    return decrypted_signature == message

# --- Completed Functions based on the initial problem description ---

def RSA_sign(Kpriv, m):
    """
    Function that implements RSA digital signature.
    Kpriv: Private key in format [d, n]
    m: Original message (numeric value) to be signed.
    Returns the signed message.
    """
    d, n = Kpriv
    # In RSA digital signature, the sender signs the message (or its hash) with their private key.
    # The signature 's' is calculated as m^d mod n.
    signature = pow(m, d, n)
    return signature


def Validate_Sign(Kpub, m, s):
    """
    Function that implements RSA signature validation.
    Kpub: Public key in format [e, n]
    m: Message (numeric value) for which the signature is to be validated.
    s: The signature to validate.
    Returns True or False, indicating if the signature is valid.
    """
    e, n = Kpub
    # To validate the signature, the verifier computes s^e mod n.
    # If the result equals the original message 'm', the signature is valid.
    m_prime = pow(s, e, n)
    return bool(m_prime == m)

# --- Additional functions (hashes, second preimage) ---

def calcular_sha256(message):
    """
    Calculates the SHA-256 hash of a message.
    The message needs to be converted to bytes for hashing.
    """
    message_bytes = str(message).encode('utf-8') 
    hash_object = hashlib.sha256(message_bytes)
    hash_hex = hash_object.hexdigest()
    return hash_hex

def segona_preimatge(message):
    """
    Attempts to find a second preimage for the given message's hash within 1,000,000 iterations.
    This function demonstrates the concept but will not practically find a preimage for SHA-256.
    
    message: The original message (integer or string) whose hash we want to find a second preimage for.
    
    Returns a different message (the second preimage) if found, otherwise None.
    """
    target_hash = calcular_sha256(message)
    
    MAX_ITERATIONS = 1000000
    # Assume a standard bit length for random candidates, related to SHA-256 output size.
    # This addresses the "numero de bits" requirement conceptually without changing the signature.
    CANDIDATE_BIT_LENGTH = 256 


    for i in range(MAX_ITERATIONS):
        # Generate a random integer as a candidate message
        candidate_message = random.getrandbits(CANDIDATE_BIT_LENGTH)

        # Ensure the candidate is not the original message itself (unless message is a string, then it won't be equal)
        # We need to ensure we're finding a *different* message.
        if isinstance(message, int) and candidate_message == message:
            continue
        
        candidate_hash = calcular_sha256(candidate_message)
        
        if candidate_hash == target_hash:
            return candidate_message # Return the found message
            
    return None # Return None if no second preimage is found

if __name__ == '__main__':
    length = 1024  # Longitud de les claus en bits
    public, private = generate_keypair(length)
    
    print("Clau pública:", public)
    print("Clau privada:", private)
    
    message = 123456789123456789123456789
    encrypted_msg = encrypt(public, message)
    decrypted_msg = decrypt(private, encrypted_msg)

    s = RSA_sign(private, message)
    validació=Validate_Sign(public,message,s)
    print("Validació signatura: ",validació)

    hash_resultat = calcular_sha256(message)
    print("El hash SHA-256 de '{texto}' es: ", hash_resultat)

    resultat = segona_preimatge(message)
    if resultat:
        print("Segona preimatge trobada: ", resultat)
    else:
        print("Cap segona preimatge trobada.")