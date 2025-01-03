#!/usr/bin/env sage

from sage.all import GF, PolynomialRing
import ecdsa
import random
import bitcoinlib
import asn1
import hashlib
import sys

from populate import populate

def separator():
	print("-" * 150)

argv = sys.argv
print(argv)
file = open(argv[1], "r")
out = open("../signatures/results.txt", "a")
f = file.read().split("\n")
pk_target = f[0].strip()
signatures = f[1:]

#####################
# global parameters #
#####################

# choose any curve
usedcurve = ecdsa.curves.SECP256k1
# usedcurve = ecdsa.curves.NIST521p
# usedcurve = ecdsa.curves.BRAINPOOLP160r1

separator()
print("Selected curve :")
print(usedcurve.name)
separator()

# the private key that will be guessed
g = usedcurve.generator
#d = random.randint(1, usedcurve.order - 1)
#print("TYPES: ", type(g), type(d))

#pubkey = ecdsa.ecdsa.Public_key( g, g * d )
#privkey = ecdsa.ecdsa.Private_key( pubkey, d )
#print("Private key :")
#print(d)
#separator()

# N = the number of signatures to use, N >= 4
# the degree of the recurrence relation is N-3
# the number of unknown coefficients in the recurrence equation is N-2
# the degree of the final polynomial in d is 1 + Sum_(i=1)^(i=N-3)i

N = 6
assert N >= 4
assert N <= 10

############################################################
# nonces and signature generation with recurrence relation #
############################################################

# first, we randomly generate the coefficients of the recurrence relation
#a = []
#for i in range(N-2):
#	a.append(random.randint(1, usedcurve.order - 1))

# then, we generate the N nonces
#k = []
# the first one is random
#k.append(random.randint(1, usedcurve.order - 1))
# the other ones are computed with the recurrence equation
#for i in range(N-1):
#	new_k = 0
#	for j in range(N-2):
#		new_k += a[j]*(k[i]**j) % usedcurve.order
#	k.append(new_k)

# sanity check to see if we generated the parameters correctly
# print(k[1] % usedcurve.n)
# print((a[1]*k[0] + a[0]) % usedcurve.n)
# assert k[1] == ((a[1]*k[0] + a[0]) % usedcurve.n)

# then, we generate the signatures using the nonces
#h = []
#sgns = []
#for i in range(N):
#    digest_fnc = hashlib.new("sha256")
#    digest_fnc.update(b"recurrence test ")
#    digest_fnc.update(i.to_bytes(1, 'big'))
#    h.append(digest_fnc.digest())
# 	# get hash values as integers and comply with ECDSA
# 	# strangely, it seems that the ecdsa module does not take the leftmost bits of hash if hash size is bigger than curve... perahps is because i use low level functions
#    if usedcurve.order.bit_length() < 256:
#        h[i] = (int.from_bytes(h[i], "big") >> (256 - usedcurve.order.bit_length())) % usedcurve.order
#    else:
#    	h[i] = int.from_bytes(h[i], "big") % usedcurve.order
# 	sgns.append(privkey.sign( h[i], k[i] ))

#class sign_:
#    def __init__(self, r, s):
#        self.r = r
#        self.s = s
  
def parse_element(hex_str, offset, element_size):
    """
    :param hex_str: string to parse the element from.
    :type hex_str: hex str
    :param offset: initial position of the object inside the hex_str.
    :type offset: int
    :param element_size: size of the element to extract.
    :type element_size: int
    :return: The extracted element from the provided string, and the updated offset after extracting it.
    :rtype tuple(str, int)
    """

    return hex_str[offset:offset+element_size], offset+element_size


def dissect_signature(hex_sig):
    """
    Extracts the r, s and ht components from a Bitcoin ECDSA signature.
    :param hex_sig: Signature in  hex format.
    :type hex_sig: hex str
    :return: r, s, t as a tuple.
    :rtype: tuple(str, str, str)
    """

    offset = 0
    # Check the sig contains at least the size and sequence marker
    assert len(hex_sig) > 4, "Wrong signature format."
    sequence, offset = parse_element(hex_sig, offset, 2)
    # Check sequence marker is correct
    assert sequence == '30', "Wrong sequence marker."
    signature_length, offset = parse_element(hex_sig, offset, 2)
    # Check the length of the remaining part matches the length of the signature + the length of the hashflag (1 byte)
    #assert len(hex_sig[offset:])/2 == int(signature_length, 16) + 1, "Wrong length."
    # Get r
    marker, offset = parse_element(hex_sig, offset, 2)
    assert marker == '02', "Wrong r marker."
    len_r, offset = parse_element(hex_sig, offset, 2)
    len_r_int = int(len_r, 16) * 2   # Each byte represents 2 characters
    r, offset = parse_element(hex_sig, offset, len_r_int)
    # Get s
    marker, offset = parse_element(hex_sig, offset, 2)
    assert marker == '02', "Wrong s marker."
    len_s, offset = parse_element(hex_sig, offset, 2)
    len_s_int = int(len_s, 16) * 2  # Each byte represents 2 characters
    s, offset = parse_element(hex_sig, offset, len_s_int)
    # Get ht
    ht, offset = parse_element(hex_sig, offset, 2)
    #assert offset == len(hex_sig), "Wrong parsing."

    return r, s, ht

#for s in sgns:
#	print("Sign: ", sgns[0].s, sgns[0].r)
decoder = asn1.Decoder()


h, s, r, s_inv = populate(signatures, N)
# get signature parameters as arrays
#s_inv = []
#s = []
#r = []
#for i in range(N):
#	s.append(sgns[i].s)
#	r.append(sgns[i].r)
#	s_inv.append(ecdsa.numbertheory.inverse_mod(s[i], usedcurve.order))

# generating the private-key polynomial #
#########################################

# declaring stuff for manipulating polynomials with SAGE
Z = GF(usedcurve.order)
R = PolynomialRing(Z, names=('dd',))
(dd,) = R._first_ngens(1)

# the polynomial we construct will have degree 1 + Sum_(i=1)^(i=N-3)i in dd
# our task here is to compute this polynomial in a constructive way starting from the N signatures in the given list order
# the generic formhjula will be given in terms of differences of nonces, i.e. k_ij = k_i - k_j where i and j are the signature indexes
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


separator()
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
    pk = ecdsa.ecdsa.Public_key(g, g * int(i[0]))
    pk_formatted = "04" + (hex(pk.point.x())[2:] + hex(pk.point.y())[2:]).upper()
    print("Public key: ", pk_formatted)
    print("Target key: ", pk_target)
    print("Private key: ", i[0], "\n")
    if pk_formatted == pk_target:
        print("key found!!!")
        out.write("private key: ")
        out.write(str(i[0]))
        out.write("\n")
        out.write("Signatures:\n")
        for s in signatures:
            out.write(s)
            out.write("\n")

file.close()
out.close()