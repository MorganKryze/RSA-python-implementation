from __future__ import annotations

import hashlib as hs

import gmpy2

KEY_SIZE = 2048

def generate_prime() -> int:
    """Generate a random prime number of size KEY_SIZE/2.

    Returns
    -------
        [int] -- [random prime number]
    """
    number = gmpy2.mpz_urandomb(rand, int(KEY_SIZE/2))
    return gmpy2.next_prime (number)

def key_gen() -> tuple:
    """Generate a public and private key pair."""
    p = generate_prime()
    q = generate_prime()
    n = gmpy2. mul(p, q)
    phi = gmpy2. mul(p-1, q-1)
    e = gmpy2.mpz_random(rand, phi)
    while (e <= 1 or gmpy2.gcd(e, phi) != 1):
        e = gmpy2.mpz_random( rand, phi)
    assert (e > 1)
    assert (e < phi)
    assert (gmpy2.gcd(e, phi) == 1)
    d = gmpy2.invert(e, phi)
    assert (d != 1)
    assert (gmpy2.t_mod(gmpy2.mul(e, d), phi) == 1)
    return (n, e, d)



def encrypt(n: int, e: int, m: int) -> int:
    """Encrypt a message using RSA encryption.

    Args:
    ----
    n (int): The product of two prime numbers p and q.
    e (int): The encryption exponent, must be co-prime with (p-1)*(q-1).
    m (int): The message to be encrypted, must be less than n.

    Returns:
    -------
    int: The encrypted message.
    """
    return gmpy2.powmod(m, e, n)

def decrypt(n: int, d: int, c: int) -> int:
    """Decrypt a message using RSA decryption.

    Args:
    ----
    n (int): The product of two prime numbers p and q.
    d (int): The decryption exponent, must be the inverse of e mod (p-1)*(q-1).
    c (int): The ciphertext to be decrypted, must be less than n.

    Returns:
    -------
    int: The decrypted message.
    """
    return gmpy2.powmod(c, d, n)


def sign(n: int, d: int, m: int | str) -> int:
    """Sign a message using RSA signature.

    Args:
    ----
    n (int): The product of two prime numbers p and q.
    d (int): The decryption exponent, must be the inverse of e mod (p-1)*(q-1).
    m (int): The message to be signed, must be less than n.

    Returns:
    -------
    int: The signature of the message.
    """
    hashed = int(hs.sha256(str(m).encode("utf-8")).hexdigest(), 16)
    return gmpy2.powmod(hashed, d, n)

def verify(n: int, e: int, m: int | str, s: int | str) -> bool:
    """Verify a message using RSA signature.

    Args:
    ----
    n (int): The product of two prime numbers p and q.
    e (int): The encryption exponent, must be co-prime with (p-1)*(q-1).
    m (int): The message to be verified, must be less than n.
    s (int): The signature of the message, must be less than n.

    Returns:
    -------
    bool: True if the signature is valid, False otherwise.
    """
    hashed = int(hs.sha256(str(m).encode("utf-8")).hexdigest(), 16)
    return gmpy2.mod(hashed, n) == gmpy2.powmod(s, e, n)



if __name__ == "__main__":
    rand = gmpy2.random_state()

    message = gmpy2.mpz_urandomb(rand, 16)
    long_message = gmpy2.mpz_urandomb(rand, 2048)
    text_message = "Hello World"
    n, e, d = key_gen()

    print("public key: ", (n, e), "\n")

    print ("secret key: ", d, "\n")

    print ("message: ", message, "\n")

    print("ciphertext: ", encrypt(n, e, message), "\n")

    assert (decrypt(n, d, encrypt(n, e, message)) == message)

    print("long message: ", long_message, "\n")

    s = sign(n, d, long_message)

    print("signature: ", s, "\n")

    print("verify: ", verify(n, e, long_message, s), "\n")

    assert (verify(n, e, text_message, sign(n, d, text_message)))
