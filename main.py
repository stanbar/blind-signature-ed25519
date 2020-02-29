import ed25519
import sys
import binascii

secret = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
public = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
message = ""
signature = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"

secret_bin: bytes = (binascii.unhexlify(secret))[:32]
public_bin: bytes = binascii.unhexlify(public)
message_bin: bytes = binascii.unhexlify(message)

normal_sign: bytes = ed25519.sign(secret_bin, message_bin)
print(ed25519.verify(public_bin, message_bin, normal_sign))

# Blind signatre
k: int = ed25519.get_k()
R: tuple = ed25519.get_R(k)
a: int = ed25519.random_int()
b: int = ed25519.random_int()
r_prim, e = ed25519.get_r_prim_and_e(secret_bin, public_bin, message_bin, R, a, b)
s: int = ed25519.get_s(e, secret_bin, k)
s_prim: int = ed25519.get_s_prim(s, a)

blind_sign: bytes = ed25519.blind_sign(r_prim, s_prim)

print(ed25519.verify(public_bin, message_bin, blind_sign))