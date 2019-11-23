from random import randrange
from hashlib import sha1
from gmpy2 import xmpz,to_binary,invert,powmod,is_prime
import socket
import sys
import pickle

def validate_sign(r, s, q):
    if r < 0 and r > q:
        return False
    if s < 0 and s > q:
        return False
    return True

def generate_g(p, q):
    while True:
        h = 2
        exp = xmpz((p - 1) // q)
        g = powmod(h, exp, p)
        if g > 1:
            break
    return g

def verify(M, r, s, p, q, g, y):
    if not validate_sign(r, s, q):
        return False
    try:
        w = invert(s, q)
    except ZeroDivisionError:
        return False
    m = int(sha1(M).hexdigest(), 16)
    u1 = (m * w) % q
    u2 = (r * w) % q
    v = (powmod(g, u1, p) * powmod(y, u2, p)) % p % q
    if v == r:
        return True
    return False

if __name__ == "__main__":
    p = 99528000845113977179280135057556905445364418460826661982741434394774395393367324563030454584752587607511502113473812008131604852272676860461074485154027132234876993823920874230010494656744070000804627484670339786102172175914015562487487183492371859771638039321912946168185032677657470918465203409563666204943
    q = 1367618368300435700925816255674517577959885975497
    g = generate_g(p,q)
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.connect(('127.0.0.1',3000))
    data_string = sock.recv(4096)
    try:
        msg = pickle.loads(data_string)
    except EOFError:
        pass
    M = msg[0]
    r = msg[1]
    s = msg[2]
    y = msg[3]
    print(M.decode("ascii"))
    print(msg)
    try:
        if verify(M, r, s, p, q, g, y):
            print('Signature verification successful')
        else:
            print("Signature verification unsuccessful")
    except Exception:
        print("invalid params")
    finally:
        pass
