#!/usr/bin/env sage

from sage.all import GF, PolynomialRing
import hashlib
import ecdsa
import random

def separator():
	print("-" * 150)


#####################
# global parameters #
#####################

# choose any curve
usedcurve = ecdsa.curves.SECP256k1
# usedcurve = ecdsa.curves.NIST521p
# usedcurve = ecdsa.curves.BRAINPOOLP160r1

print("Selected curve :")
print(usedcurve.name)
separator()

# the private key that will be guessed
g = usedcurve.generator
d = random.randint(1, usedcurve.order - 1)
print("TYPES: ", type(g), type(d))

pubkey = ecdsa.ecdsa.Public_key( g, g * d )
privkey = ecdsa.ecdsa.Private_key( pubkey, d )
print("Private key :")
print(d)
separator()

# N = the number of signatures to use, N >= 4
# the degree of the recurrence relation is N-3
# the number of unknown coefficients in the recurrence equation is N-2
# the degree of the final polynomial in d is 1 + Sum_(i=1)^(i=N-3)i

N = 4
assert N >= 4

############################################################
# nonces and signature generation with recurrence relation #
############################################################

# first, we randomly generate the coefficients of the recurrence relation
a = []
for i in range(N-2):
	a.append(random.randint(1, usedcurve.order - 1))

# then, we generate the N nonces
k = []
# the first one is random
k.append(random.randint(1, usedcurve.order - 1))
# the other ones are computed with the recurrence equation
for i in range(N-1):
	new_k = 0
	for j in range(N-2):
		new_k += a[j]*(k[i]**j) % usedcurve.order
	k.append(new_k)

# sanity check to see if we generated the parameters correctly
# print(k[1] % usedcurve.n)
# print((a[1]*k[0] + a[0]) % usedcurve.n)
# assert k[1] == ((a[1]*k[0] + a[0]) % usedcurve.n)

# then, we generate the signatures using the nonces
h = []
sgns = []
for i in range(N):
	digest_fnc = hashlib.new("sha256")
	digest_fnc.update(b"recurrence test ")
	digest_fnc.update(i.to_bytes(1, 'big'))
	h.append(digest_fnc.digest())
	# get hash values as integers and comply with ECDSA
	# strangely, it seems that the ecdsa module does not take the leftmost bits of hash if hash size is bigger than curve... perahps is because i use low level functions
	if usedcurve.order.bit_length() < 256:
		h[i] = (int.from_bytes(h[i], "big") >> (256 - usedcurve.order.bit_length())) % usedcurve.order
	else:
		h[i] = int.from_bytes(h[i], "big") % usedcurve.order
	sgns.append(privkey.sign( h[i], k[i] ))

class sign_:
    def __init__(self, r, s):
        self.r = r
        self.s = s
  

#for s in sgns:
#	print("Sign: ", sgns[0].s, sgns[0].r)
sgns = [
    sign_("7FFB498DF52973A68BE7133DF3545CA9C48BE7B894230F92DF5545AB1F163F17",
          "0080E0FF45BB9330588FF66EDCB63F622EA38305AEA0DA2315ACC9162C2F2A215D"),
    sign_("009FA460837830A7FA516BCAE2A8281722D9EAAB02672D4B9B4187E98B020E6E6C",
          "56D414CC1EEA2E1AF6BE289E3A9ABB61CEA2D770B3FA4A442BCB4781F94FE004"),
    sign_("07EDC368DD34354CCC48E317CCB9BC6BD3A4A555EB8E5D819856922E097E8D14",
          "00DEC61AA3CC3CE0A8C5D4CEB7EF32632E6AAD2BAB3846B643E39BEAA492457A6B"),
    sign_("6EA8A830172366C19AC3CBAF8833B0DF5818D42AC977595FDAD3560841AE0D68",
          "008F214CC8335ED0587DCE9B7E32B85F12F2FE61094C6F5C2B644A92E73AF001F8"),
    ]

#for i in sgns:
#	print(i.r)
# get signature parameters as arrays
s_inv = []
s = []
r = []
for i in range(N):
	s.append(int(sgns[i].s, 16))
	r.append(int(sgns[i].r, 16))
	s_inv.append(ecdsa.numbertheory.inverse_mod(s[i], usedcurve.order))


#########################################
# generating the private-key polynomial #
#########################################

# declaring stuff for manipulating polynomials with SAGE
Z = GF(usedcurve.order)
R = PolynomialRing(Z, names=('dd',))
(dd,) = R._first_ngens(1)

# the polynomial we construct will have degree 1 + Sum_(i=1)^(i=N-3)i in dd
# our task here is to compute this polynomial in a constructive way starting from the N signatures in the given list order
# the generic formula will be given in terms of differences of nonces, i.e. k_ij = k_i - k_j where i and j are the signature indexes
# each k_ij is a first-degree polynomial in dd
# this function has the goal of returning it given i and j
def k_ij_poly(i, j):
	hi = Z(h[i])
	hj = Z(h[j])
	s_invi = Z(s_inv[i])
	s_invj = Z(s_inv[j])
	ri = Z(r[i])
	rj = Z(r[j])
	poly = dd*(ri*s_invi - rj*s_invj) + hi*s_invi - hj*s_invj
	return poly

# the idea is to compute the polynomial recursively from the given degree down to 0
# the algorithm is as follows:
# for 4 signatures the second degree polynomial is:
# k_12*k_12 - k_23*k_01
# so we can compute its coefficients.
# the polynomial for N signatures has degree 1 + Sum_(i=1)^(i=N-3)i and can be derived from the one for N-1 signatures

# let's define dpoly(i, j) recursively as the dpoly of degree i starting with index j

def dpoly(n, i, j):
	if i == 0:
		return (k_ij_poly(j+1, j+2))*(k_ij_poly(j+1, j+2)) - (k_ij_poly(j+2, j+3))*(k_ij_poly(j+0, j+1))
	else:
		left = dpoly(n, i-1, j)
		for m in range(1,i+2):
			left = left*(k_ij_poly(j+m, j+i+2))
		right = dpoly(n, i-1, j+1)
		for m in range(1,i+2):
			right = right*(k_ij_poly(j, j+m))
		return (left - right)

def print_dpoly(n, i, j):
	if i == 0:
		print('(k', j+1, j+2, '*k', j+1, j+2, '-k', j+2, j+3, '*k', j+0, j+1, ')', sep='', end='')
	else:
		print('(', sep='', end='')
		print_dpoly(n, i-1, j)
		for m in range(1,i+2):
			print('*k', j+m, j+i+2, sep='', end='')
		print('-', sep='', end='')
		print_dpoly(n, i-1, j+1)
		for m in range(1,i+2):
			print('*k', j, j+m, sep='', end='')
		print(')', sep='', end='')


print("Nonces difference equation :")
print_dpoly(N-4, N-4, 0)
print(' = 0', sep='', end='')
print()
separator()

poly_target = dpoly(N-4, N-4, 0)
print("Polynomial in d :")
print(poly_target)
separator()

d_guesses = poly_target.roots()
print("Roots of the polynomial :")
print(d_guesses)
separator()

# check if the private key is among the roots
for i in d_guesses:
	print(i[0])
	if i[0] == d:
		print("key found!!!")