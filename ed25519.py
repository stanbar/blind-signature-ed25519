import hashlib
import random


def sha512(s: bytes) -> bytes:
    return hashlib.sha512(s).digest()


# Base field Z_p
p: int = 2**255 - 19


def modp_inv(x) -> int:
    return pow(x, p-2, p)


# Curve constant
d: int = -121665 * modp_inv(121666) % p

# Group order
q: int = 2**252 + 27742317777372353535851937790883648493


def sha512_modq(s) -> int:
    return int.from_bytes(sha512(s), "little") % q


# Points are represented as tuples (X, Y, Z, T) of extended coordinates,
# with x = X/Z, y = Y/Z, x*y = T/Z

def point_add(P: tuple, Q: tuple) -> tuple:
    A = (P[1]-P[0])*(Q[1]-Q[0]) % p
    B = (P[1]+P[0])*(Q[1]+Q[0]) % p
    C = 2 * P[3] * Q[3] * d % p
    D = 2 * P[2] * Q[2] % p
    E = B-A
    F = D-C
    G = D+C
    H = B+A
    return (E*F, G*H, F*G, E*H)

# Computes Q = s * Q


def point_mul(s, P) -> tuple:
    Q = (0, 1, 1, 0)  # Neutral element
    while s > 0:
        # Is there any bit-set predicate?
        if s & 1:
            Q = point_add(Q, P)
        P = point_add(P, P)
        s >>= 1
    return Q


def point_equal(P, Q):
    # x1 / z1 == x2 / z2  <==>  x1 * z2 == x2 * z1
    if (P[0] * Q[2] - Q[0] * P[2]) % p != 0:
        return False
    if (P[1] * Q[2] - Q[1] * P[2]) % p != 0:
        return False
    return True


# Square root of -1
modp_sqrt_m1: int = pow(2, (p-1) // 4, p)

# Compute corresponding x coordinate, with low bit corresponding to
# sign, or return None on failure


def recover_x(y, sign):
    if y >= p:
        return None
    x2 = (y*y-1) * modp_inv(d*y*y+1)
    if x2 == 0:
        if sign:
            return None
        else:
            return 0

    # Compute square root of x2
    x = pow(x2, (p+3) // 8, p)
    if (x*x - x2) % p != 0:
        x = x * modp_sqrt_m1 % p
    if (x*x - x2) % p != 0:
        return None

    if (x & 1) != sign:
        x = p - x
    return x


# Base point
g_y: int = 4 * modp_inv(5) % p
g_x = recover_x(g_y, 0)
G: tuple = (g_x, g_y, 1, g_x * g_y % p)


def point_compress(P: tuple) -> bytes:
    zinv = modp_inv(P[2])
    x = P[0] * zinv % p
    y = P[1] * zinv % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def point_decompress(s: bytes) -> tuple:
    if len(s) != 32:
        raise Exception("Invalid input length for decompression")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1

    x = recover_x(y, sign)
    if x is None:
        return None
    else:
        return (x, y, 1, x*y % p)


def secret_expand(secret: bytes) -> (int, bytes):
    if len(secret) != 32:
        raise Exception("Bad size of private key")
    h = sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    return (a, h[32:])


def secret_to_public(secret: bytes) -> bytes:
    (a, dummy) = secret_expand(secret)
    return point_compress(point_mul(a, G))


def sign(secret: bytes, msg: bytes) -> bytes:
    (a, dummy) = secret_expand(secret)
    A: bytes = secret_to_public(secret)
    r: int = random_int()
    R: tuple = point_mul(r, G)  # g^k mod p
    Rs: bytes = point_compress(R)
    h: int = sha512_modq(Rs + msg)
    s: int = (r + h * a) % q
    S = int.to_bytes(s, 32, "little")
    return Rs + S


def get_k() -> int:
    k = random_int()
    return k


def get_R(k: int) -> tuple:
    R = point_mul(k, G)
    return R


def random_int() -> int:
    return random.randint(1, q-1)


def get_r_prim_and_e(secret: bytes, public: bytes, message: bytes, R: tuple, alpha: int, beta: int) -> (tuple, int):
    # r’ = r*(g^a)*(y^b) mod p
    # g^a
    aG: tuple = point_mul(alpha, G)

    x, prefix = secret_expand(secret)
    A: tuple = point_mul(x, G)
    bA: tuple = point_mul(beta, A)

    r_prim: tuple = point_add(point_add(R, aG), bA)
    Rs: bytes = point_compress(r_prim)
    # e’ = H(M || r’)
    e_prim: int = int.from_bytes(sha512(Rs + message), "little")  # point_compress not sure here
    # e = e’ – b mod q
    e: int = (e_prim + beta) % q
    return (r_prim, e)


def get_s(e, secret: bytes, k: int) -> int:
    # s = ex + k mod q
    x, prefix = secret_expand(secret)
    s: int = (e * x + k) % q
    return s


def get_s_prim(s: tuple, alpha: tuple) -> int:
    # s_pri = s - a mod q
    s_pri: int = (s + alpha) % q
    return s_pri


def blind_sign(r_prim: tuple, s_prim: int) -> bytes:
    Rs: bytes = point_compress(r_prim)
    S: bytes = int.to_bytes(s_prim, 32, "little")
    return Rs + S


def verify(public, msg, signature):
    if len(public) != 32:
        raise Exception("Bad public key length")
    if len(signature) != 64:
        Exception("Bad signature length")
    
    A: tuple = point_decompress(public)
    if not A:
        return False
    Rs: bytes = signature[:32]
    R: tuple = point_decompress(Rs)
    if not R:
        return False
    s: int = int.from_bytes(signature[32:], "little")
    h: int = sha512_modq(Rs + msg)
    sB: tuple = point_mul(s, G)
    hA: tuple = point_mul(h, A)
    return point_equal(sB, point_add(R, hA))
