from populate import populate
import pytest

signatures_data = [
    ([
        "3046022100B7D9ED351F82EBFEA2D7584B0733404AFBD2043093250FF6CA681AFE89B5B32A0221009F5061BBF4640CC9177D0DCCF30848F698367B9F0A3B7D74008A60ABDFA69DC9",
        "304502200457036709DDD23667ABB9E870797041FAE4BF6B690A8DC71B4C2D67A26726F0022100DAD318FBD374BD6A21ADE3AFBCD22005711048BCB8E7675C13BF0C071ADDCF44"
    ], [
        57004006673939934145591975114605949722813110540060845765423670244002893523596, 
        107865291548562097089322179101144521012866721496993258702963060162551320693665
    ], 
        ([83158294249874560363094736047011164713402796541257339415024030027458945594154,
          1962990572121394628678104845112500634453108399580403703450930405129754978032],
         [72059765226564649266173127814164578341165287917963358200395088787048078155209,
          98977178152948165738985072799549183231339756475941213953197767183933544189764])
    ),
    ([], [], ([], []))
]

hash_data = [[], []]

@pytest.mark.parametrize("signatures, _, __", signatures_data)
def test_lenghts(signatures, _, __):
    N = len(signatures)
    h, s, r, s_inv = populate(signatures, N)
    assert len(h) == len(s) == len(r) == len(s_inv) == N

@pytest.mark.parametrize("signatures, expected_hash, _", signatures_data)
def test_hash(signatures, expected_hash, _):
    N = len(signatures)
    h, _, _, _ = populate(signatures, N)
    print(h)
    assert h == expected_hash
    
@pytest.mark.parametrize("signatures, _, expected", signatures_data)
def test_s_r(signatures, _, expected):
    N = len(signatures)
    _, s, r, _ = populate(signatures, N)
    print(s)
    print(r)
    assert r == expected[0]
    assert s == expected[1]