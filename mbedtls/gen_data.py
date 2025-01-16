import hashlib
from populate import dissect_signature
import itertools

l = list(itertools.product(range(0,16), repeat=4))
for i in l:
    file = open("../signatures/signatures.txt", "r")
    name = str(i[0])+str(i[1])+str(i[2])+str(i[3])
    out = open("./data/data"+name+".json", "w")
    f = file.read().split("\n")
    public_key = f[0].strip()
    signatures = f[1:]

    public_uncompressed = public_key[2:]
    public_x = int(public_uncompressed[:64], 16)
    public_y = int(public_uncompressed[64:], 16)

    formatted_signatures = ""
    for idx, s in enumerate(signatures):
        message = str(idx)
        digest_fnc = hashlib.new("sha256")
        digest_fnc.update(message.encode('utf-8'))
        digest = str(int(digest_fnc.hexdigest(), 16))
        if(len(s) < 1):
            break
        r, s, _ = dissect_signature(s)
        print(r,s)
        formatted_signatures += '{ "r": ' + str(int(r, 16)) + ', "s": ' + str(int(s, 16)) + ', "kp": '+str(i[idx])+', "hash": '+ digest +'},'

    out.write('{"curve": "SECP256K1", "public_key": ['+str(public_x)+', '+str(public_y)+
              '], "known_type": "LSB", "known_bits": 4, "signatures": ['+ formatted_signatures[:-1] +']}')


