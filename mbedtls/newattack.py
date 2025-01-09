#!/usr/bin/env sage

from sage.all import GF, PolynomialRing
import ecdsa
import asn1
import sys

from populate import populate

def separator():
	print("-" * 50)

argv = sys.argv
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

# N = the number of signatures to use, N >= 4
# the degree of the recurrence relation is N-3
# the number of unknown coefficients in the recurrence equation is N-2
# the degree of the final polynomial in d is 1 + Sum_(i=1)^(i=N-3)i

N = 5
assert N >= 4
assert N <= 10

############################################################
# nonces and signature generation with recurrence relation #
############################################################

h, s, r, s_inv = populate(signatures, N)

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


#separator()
#print("Nonces difference equation :")
#print_dpoly(N-4, N-4, 0)
#print(' = 0', sep='', end='')
#print()
#separator()

poly_target = dpoly(N-4, N-4, 0)
#print("Polynomial in d :")
#print(poly_target)
#separator()

d_guesses = poly_target.roots()
#print("Roots of the polynomial :")
#print(d_guesses)
#separator()

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