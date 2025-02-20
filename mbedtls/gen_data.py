import hashlib
from populate import dissect_signature
import itertools
import subprocess
import nest_asyncio
nest_asyncio.apply()

N = 6
l = list(itertools.product(range(0,2), repeat=N))
l = range(0, 2**N)
for i in l:
    file = open("../signatures/mock.txt", "r")
    result = subprocess.run(["./ecdsa", "10"], capture_output=True, text=True)
    name = ""+str(i)
    #for j in range(0,N):
    #    name += str(i[j])
    out = open("./data/data"+name+".json", "w")
    
    f = result.stdout.split("\n")
    public_key = f[0].strip()
    signatures = f[1].split(" ")

    public_uncompressed = public_key[2:]
    public_x = int(public_uncompressed[:64], 16)
    public_y = int(public_uncompressed[64:], 16)

    formatted_signatures = ""
    #kb = "".join([str(x) for x in i])
    for idx, sig in enumerate(signatures):
        message = str(idx)
        digest_fnc = hashlib.new("sha256")
        digest_fnc.update(message.encode('utf-8'))
        digest = str(int(digest_fnc.hexdigest(), 16))
        if(len(sig) < 1):
            break
        r, s, _ = dissect_signature(sig)
        formatted_signatures += '{ "r": ' + str(int(r, 16)) + ', "s": ' + str(int(s, 16)) + ', "kp": '+str(i)+', "hash": '+ digest +'},'

    out.write('{"curve": "SECP256K1", "public_key": ['+str(public_x)+', '+str(public_y)+
              '], "known_type": "MSB", "known_bits": '+str(N)+', "signatures": ['+ formatted_signatures[:-1] +']}')
print("Done")

