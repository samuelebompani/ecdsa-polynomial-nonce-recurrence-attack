import hashlib

import bitcoinlib
import ecdsa

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


def populate(signatures, N):
    r = []
    s = []
    s_inv = []
    h = []
    c = 0
    usedcurve = ecdsa.curves.SECP256k1
    for sig in signatures:
        if(c >= N or len(sig) <= 1):
            break
        message = str(c)
        digest_fnc = hashlib.new("sha256")
        digest_fnc.update(message.encode('utf-8'))
        digest = digest_fnc.digest()
        h.append(int.from_bytes(digest, "big"))
        #print(digest_fnc.hexdigest().upper())
        #h.append(int.from_bytes(message.encode('utf-8'), "big"))
        #print(int.from_bytes(message.encode('utf-8')))
        r0,s0,_ = dissect_signature(sig)
        #sgn = bitcoinlib.transactions.Signature(int(r0, 16), int(s0, 16))
        #print(bitcoinlib.transactions.Signature(int(r0, 16), int(s0, 16)))
        s.append(int(s0, 16))
        r.append(int(r0, 16))
        s_inv.append(ecdsa.numbertheory.inverse_mod(s[c], usedcurve.order))
        
        #print(str(sgns[c]).upper())#, "\nR: ",hex(sgns[c].r), " S: ", hex(sgns[c].s))
        c+=1
    return h, s, r, s_inv