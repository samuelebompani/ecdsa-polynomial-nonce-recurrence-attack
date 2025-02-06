#!/usr/bin/env sage

from sage.all import GF, PolynomialRing
import ecdsa
import subprocess
import sys
import nest_asyncio
import multiprocessing
import itertools
nest_asyncio.apply()

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



def attack(n_signs):
    # Run the ecdsa signatures generator
    result = subprocess.run(["./ecdsa", n_signs], capture_output=True, text=True)
    output = result.stdout.split("\n")

    assert len(output) > 0

    # The first line of the output are the messages
    messages = output[0].split()

    # The second line of the output is the target public key
    target_key = output[1]

    # The third line of the output are the hashes of the messages
    h = list(map(lambda x: int(x, 16), output[2].split()))

    # The fourth line of the output are the signatures
    signatures = output[3].split()

    # The used curve is SECP256k1
    usedcurve = ecdsa.curves.SECP256k1
    g = usedcurve.generator
    
    # N = the number of signatures to use, N >= 4
    # the degree of the recurrence relation is N-3
    # the number of unknown coefficients in the recurrence equation is N-2
    # the degree of the final polynomial in d is 1 + Sum_(i=1)^(i=N-3)i
    N = len(signatures)
    assert N >= 4
    assert N <= 10

    # declaring stuff for manipulating polynomials with SAGE
    Z = GF(usedcurve.order)
    R = PolynomialRing(Z, names=('dd',))
    (dd,) = R._first_ngens(1)
    
    success = []
    fail = 0

    # Try the attack for each permutation of the signatures
    for signs in itertools.permutations(signatures):
        # Extract r and s from the signatures
        r = []
        s = []
        s_inv = []
        c = 0
        for sig in signs:
            r0,s0,_ = dissect_signature(sig)
            r.append(int(r0, 16))
            s.append(int(s0, 16))
            s_inv.append(ecdsa.numbertheory.inverse_mod(s[c], usedcurve.order))
            c += 1

        # print("Target key: ", target_key)
        # print("Hashes: ", h)
        # print("Signatures: ", signs)
    
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

        poly_target = dpoly(N-4, N-4, 0)
        d_guesses = poly_target.roots()

        s = []
        f = 0
        for i in d_guesses:
            pk = ecdsa.ecdsa.Public_key(g, g * int(i[0]))
            pk_formatted = "04" + (hex(pk.point.x())[2:] + hex(pk.point.y())[2:]).upper()
            # print("Public key: ", pk_formatted)
            # print("Target key: ", target_key)
            # print("Private key: ", i[0], "\n")
            if pk_formatted == target_key:
                print("Private key: ", i[0], "\n")
                success.append({"private": i[0], "public": pk_formatted})
            else:
                f += 1
        fail += f
        success = success + s
    return (fail, success)

def main():
    argv = sys.argv
    assert argv[1]
    limit = int(argv[1])
    assert argv[2]
    n_signs = argv[2]
    # Compile the ECDSA signatures generator
    subprocess.run(["make"])
    
    success = []
    fail = 0
    
    # Use multiprocessing to execute the attack in parallel
    with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
        results = pool.map(attack, [n_signs] * limit)

    # Aggregate results
    fail = sum(result[0] for result in results)
    success = [item for result in results for item in result[1]]
    
    # Print the results
    print("Wrong guesses: ", fail)
    print("Success: ", success)
        
if __name__ == "__main__":
    main()