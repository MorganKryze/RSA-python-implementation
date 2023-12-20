from __future__ import annotations

import hashlib as hs

import gmpy2


def my_gcd(a: int, b: int) -> int:
    """Calculate the greatest common divisor of two numbers.

    Args:
    ----
    a (int): The first number.
    b (int): The second number.

    Returns:
    -------
    int: The greatest common divisor of the two numbers.
    """
    while b != 0:
        a, b = b, a % b
    return a

def my_invert(a: int, b: int) -> int | None:
    """Calculate the inverse of a mod b.

    Args:
    ----
    a (int): The number to be inverted.
    b (int): The modulus.

    Returns:
    -------
    int: The inverse of a mod b.
    """
    if my_gcd(a, b) != 1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, b
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % b

def my_powmod(a: int, b: int, c: int) -> int:
    """Calculate a^b mod c.

    Args:
    ----
    a (int): The base.
    b (int): The exponent.
    c (int): The modulus.

    Returns:
    -------
    int: a^b mod c.
    """
    result = 1
    while b > 0:
        if b & 1:
            result = (result * a) % c
        b >>= 1
        a = (a * a) % c
    return result

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
    assert (my_gcd(e, phi) == 1)
    d = my_invert(e, phi)
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
    return my_powmod(m, e, n)

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
    return my_powmod(c, d, n)


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
    return my_powmod(hashed, d, n)

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
    return gmpy2.mod(hashed, n) == my_powmod(s, e, n)



if __name__ == "__main__":
    KEY_SIZE = 2048
    rand = gmpy2. random_state()

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
