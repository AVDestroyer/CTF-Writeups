from Crypto.Util.number import inverse
from hashlib import sha256
import os
import signal
from pwn import *

MODS = [
942340315817634793955564145941,
743407728032531787171577862237,
738544131228408810877899501401,
1259364878519558726929217176601,
1008010020840510185943345843979,
1091751292145929362278703826843,
793740294757729426365912710779,
1150777367270126864511515229247,
763179896322263629934390422709,
636578605918784948191113787037,
1026431693628541431558922383259,
1017462942498845298161486906117,
734931478529974629373494426499,
934230128883556339260430101091,
960517171253207745834255748181,
746815232752302425332893938923, 
]


class NonceGenerator:
    def __init__(self):
        self.state = os.urandom(10)
        self.db = {}
    
    def gen(self):
        self.state = sha256(self.state + b'wow').digest()[:10]
        key = sha256(self.state).digest()[:8]
        self.db[key] = self.state

        return int.from_bytes(self.state, 'big'), key

    def get(self, key: str):
        if key not in self.db:
            print("Wrong key :(")
            exit(0)

        return int.from_bytes(self.db[key], 'big')
    
    def setState(self,state):
        self.state = state

class ECPoint:
    def __init__(self, point, mod):
        self.x = point[0]
        self.y = point[1]
        self.mod = mod

    def inf(self):
        return ECPoint((0, 0), self.mod)

    def _is_inf(self):
        return self.x == 0 and self.y == 0

    def __eq__(self, other):
        assert self.mod == other.mod
        return self.x == other.x and self.y == other.y

    def __add__(self, other):
        assert self.mod == other.mod
        P, Q = self, other
        if P._is_inf() and Q._is_inf():
            return self.inf()
        elif P._is_inf():
            return Q
        elif Q._is_inf():
            return P

        if P == Q:
            lam = (3 * P.x**2 - 3) * inverse(2 * P.y, self.mod) % self.mod
        elif P.x == Q.x:
            return self.inf()
        else:
            lam = (Q.y - P.y) * inverse(Q.x - P.x, self.mod) % self.mod

        x = (lam**2 - P.x - Q.x) % self.mod
        y = (lam * (P.x - x) - P.y) % self.mod

        return ECPoint((x, y), self.mod)

    def __rmul__(self, other: int):
        base, ret = self, self.inf()
        while other > 0:
            if other & 1:
                ret = ret + base
            other >>= 1
            base = base + base
        return ret


class MyECCService:
    BASE_POINT = (2, 3)
    def __init__(self):
        self.nonce_gen = NonceGenerator()

    def get_x(self, nonce: int) -> bytes:
        ret = b""
        for mod in MODS:
            p = ECPoint(self.BASE_POINT, mod)
            x = (nonce * p).x
            ret += int(x).to_bytes(13, "big")
        return ret

    def gen(self) -> bytes:
        nonce, key = self.nonce_gen.gen()
        x = self.get_x(nonce)

        return b"\x02\x03" + key + x

    def verify(self, inp: bytes) -> bool:
        assert len(inp) == 218

        nonce = self.nonce_gen.get(inp[2:10])
        self.BASE_POINT = (inp[0], inp[1])
        x = self.get_x(nonce)
        return inp[10:] == x

    def setState(self, nonce: bytes):
        self.nonce_gen.setState(nonce)

def handler(_signum, _frame):
    print("Time out!")
    exit(0)


def main():
    conn = remote('my-ecc-service.chal.perfect.blue',int(1337))
    conn.recvuntil(b' ')

    conn.send(b"G\n")
    payloadHex = conn.recvline().decode().strip().split()[1]
    print(payloadHex)
    
    
    E1 = EllipticCurve(GF(MODS[-4]),[-3,7])
    E2 = EllipticCurve(GF(MODS[-3]),[-3,7])
    nums = [payloadHex[i+20:i+20+26] for i in range(0,len(payloadHex[20:]),26)]
    a1 = nums[-4]
    a2 = nums[-3]

    print(nums)


    x1 = int.from_bytes(bytes.fromhex(a1),"big")
    x2 = int.from_bytes(bytes.fromhex(a2),"big")
    P1 = E1(2,3)
    P2 = E2(2,3)
    y11 = mod(pow(x1,3)-3*x1+7,MODS[-4]).sqrt()
    y12 = (-1*y11)% MODS[-4]
    y21 = mod(pow(x2,3)-3*x2+7,MODS[-3]).sqrt()
    y22 = (-1*y21) % MODS[-3]
    Q11 = E1(x1,y11)
    Q12 = E1(x1,y12)
    Q21 = E2(x2,y21)
    Q22 = E2(x2,y22)
            

    nonce1 = P1.discrete_log(Q11)
    nonce2 = P1.discrete_log(Q12)
 
    nonce3 = P2.discrete_log(Q21)
    nonce4 = P2.discrete_log(Q22)
            
    nonce = 0

    if (nonce1 == nonce3 or nonce1 == nonce4):
        nonce = nonce1
    else:
        nonce = nonce2
            
    print(nonce)
    print(int(nonce).to_bytes(10,"big"))

    testService = MyECCService()
    testService.setState(int(nonce).to_bytes(10,"big"))
    newPayload = testService.gen()
    print(f"Result: {newPayload.hex()}")
    conn.send(b"P\r\n")
    conn.interactive()
    

if __name__ == "__main__":
    main()
