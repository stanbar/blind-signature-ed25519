import hashlib
import os
import random

def _hash(m):
	return hashlib.sha512(m).digest()

def bit(h, i):
	return (ord(h[i/8]) >> (i % 8)) & 1

#------------------------------------------------------------------------------

class FieldElement(object):

	q = 2**255 - 19

	def __init__(self, x):
		self.x = x

	def __add__(self, other):
		return FieldElement((self.x + other.x) % self.q)

	def __sub__(self, other):
		return FieldElement((self.x - other.x) % self.q)

	def __mul__(self, other):
		return FieldElement((self.x * other.x) % self.q)

	def __neg__(self):
		return FieldElement(self.q - self.x)

	def __str__(self):
		return str(self.x)

	@staticmethod
	def invert(t):
		return FieldElement(pow(t.x, FieldElement.q - 2, FieldElement.q))

	@staticmethod
	def square(x):
		return FieldElement((x * x) % FieldElement.q)

#------------------------------------------------------------------------------

class GroupElementProjective(object):

	d = FieldElement(37095705934669439343138083508754565189542113879843219016388785533085940283555)

	def __init__(self, x, y, z):
		self.x = x
		self.y = y
		self.z = z

	def __add__(self, other):
		# 11M + 1S + 6A

		A = self.z * other.z
		B = A * A
		C = self.x * other.x
		D = self.y * other.y
		E = self.d * (C * D)
		F = B - E
		G = B + E
		H = C + D

		x = A * F * ((self.x + self.y) * (other.x + other.y) - H)
		y = A * G * H
		z = F * G
		return GroupElementProjective(x, y, z)

	def __sub__(self, other):
		return self + (-other)

	def __neg__(self):
		return GroupElementProjective(-self.x, self.y, self.z)

	def __str__(self):
		return "({x}, {y}, {z})".format(x = str(self.x), y = str(self.y), z = str(self.z))

	def double(self):
		# 3M + 4S + 6A

		sum2 = (self.x + self.y) * (self.x + self.y)
		x2 = self.x * self.x
		y2 = self.y * self.y
		z2 = self.z * self.z

		e = x2 + y2
		f = x2 - y2
		j = z2 + z2 + f

		self.x = (e - sum2) * j
		self.y = f * e
		self.z = f * j

	def serialize(self):
		return GroupElement.from_projective(self).serialize()

#------------------------------------------------------------------------------

class GroupElement(object):

	def __init__(self, x, y):
		self.x = x
		self.y = y

	def __add__(self, other):
		res = self.to_projective() + other.to_projective()
		return GroupElement.from_projective(res)

	def __sub__(self, other):
		res = self.to_projective() + (-other).to_projective()
		return GroupElement.from_projective(res)

	def __neg__(self):
		return GroupElement(-self.x, self.y)

	def __str__(self):
		return "({x}, {y})".format(x = str(self.x.x),y = str(self.y.x))

	def to_projective(self):
		return GroupElementProjective(self.x, self.y, FieldElement(1))

	def serialize(self):

		bits = [(self.y.x >> i) & 1 for i in xrange(256 - 1)] + [self.x.x & 1]
		return ''.join([
			chr(sum([bits[i * 8 + j] << j for j in xrange(8)]))
			for i in xrange(256/8)
		])

	@staticmethod
	def from_projective(p):
		inverse = FieldElement.invert(p.z)
		x = p.x * inverse
		y = p.y * inverse
		return GroupElement(x, y)

#------------------------------------------------------------------------------

class Scalar(object):

	l = 2**252 + 27742317777372353535851937790883648493

	def __init__(self, value):
		if (type(value) == Scalar):
			self.x = value.x
		else:
			self.x = value

	def __add__(self, other):
		return Scalar((self.x + other.x) % self.l)

	def __sub__(self, other):
		return Scalar((self.x - other.x) % self.l)

	def __mul__(self, other):
		t = type(other)
		if (t == GroupElementProjective):
			return scalar_multiply(self.x, other)
		elif (t == GroupElement):
			return GroupElement.from_projective(scalar_multiply(self.x, other.to_projective()))
		elif (t == Scalar):
			return Scalar(self.x * other.x)
		else:
			pass

	def __mod__(self, other):
		return Scalar(self.x % other)

	def __str__(self):
		return str(self.x)

	@staticmethod
	def hash(m):
		h = _hash(m)
		return Scalar(sum(2**i * bit(h, i) for i in xrange(512)))

	@staticmethod
	def encode(y):
		bits = [(y.x >> i) & 1 for i in xrange(256)]
		return ''.join([
			chr(sum([bits[i * 8 + j] << j for j in xrange(8)]))
			for i in xrange(256/8)
		])

	@staticmethod
	def random():
		return Scalar(random.randint(1, Scalar.l - 1))

#------------------------------------------------------------------------------

def scalar_multiply(scalar, point):

	mask, num_bits = 0, 0
	while scalar:
		mask = mask << 1 | (scalar & 1)
		scalar >>= 1
		num_bits += 1

	zero = GroupElementProjective(FieldElement(0), FieldElement(1), FieldElement(1)) 
	res = zero
	for _ in xrange(num_bits):
		res.double()
		res = res + point if (mask & 1) else res + zero
		mask >>= 1

	return res

#------------------------------------------------------------------------------

basepoint = GroupElement(
	FieldElement(15112221349535400772501151409588531511454012693041857206046113283949847762202),
	FieldElement(46316835694926478169428394003475163141307993866256225615783033603165251855960)
)

G = basepoint.to_projective()

#------------------------------------------------------------------------------

class KeyPair(object):

	def sign(self, m):
		k = Scalar.hash(self.half + m)
		R = k * G
		e = challenge(R, self.pk, m)
		s = k + e * self.x
		return R, s

	def verify(self, R, s, m):
		rb = R.serialize()
		e = challenge(rb, self.pk, m)
		res = s * G - e * self.P
		return (res.serialize() == rb)

	@staticmethod
	def from_public_point(point):

		self = KeyPair()
		self.P = point
		self.pk = self.P.serialize()
		return self

	@staticmethod
	def from_private_key(sk):

		h = _hash(sk)
		x = Scalar(2**(256-2) + sum(2**i * bit(h, i) for i in xrange(3, 256-2)))

		self = KeyPair()
		self.half = h[32:64]
		self.x = x
		self.P = x * G
		self.pk = self.P.serialize()
		return self

	@staticmethod
	def random():
		sk = os.urandom(32)
		return KeyPair.from_private_key(sk)

#------------------------------------------------------------------------------

def challenge(R, P, M):

	if (type(R) == GroupElementProjective):
		R = R.serialize()

	if (type(P) == GroupElementProjective):
		P = P.serialize()

	return Scalar.hash(R + P + M)

#
#
#

issuer = KeyPair.random()
message = 'testmessage'
r, s = issuer.sign(message)
print issuer.verify(r, s, message)

# issuer sends `(P, R)` to user

P = issuer.P
k = Scalar.random()
R = k * G

#
#
#

a = Scalar.random()
b = Scalar.random()
m = 'blinded message'

Rprim = R + a * G + b * P
eprim = challenge(Rprim, P, m)

# user sends `e` to issuer, for signing
e = eprim + b

#
#
#

# issuer signs, and sends `s` to user
s = k + e * issuer.x

#
#
#

# user sends `(Rprim, sprim)` to issuer
sprim = s + a

# issuer verifies

print issuer.verify(Rprim, sprim, m)
