from random import randrange
from hashlib import sha1
from gmpy2 import xmpz,to_binary,invert,is_prime,powmod
import socket
import sys
import pickle

def generate_g(p, q):
    while True:
        h = 2
        exp = xmpz((p - 1) // q)
        g = powmod(h, exp, p)
        if g > 1:
            break
    return g


def generate_keys(g, p, q):
    x = randrange(2, q)  # x < q
    y = powmod(g, x, p)
    return x, y

def sign(M, p, q, g, x):
    while True:
        k = randrange(2, q)  # k < q
        r = powmod(g, k, p) % q
        m = int(sha1(M).hexdigest(), 16)
        try:
            s = (invert(k, q) * (m + x * r)) % q
            return r, s
        except ZeroDivisionError:
            pass


if __name__ == '__main__':
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.bind(('',3000))
    sock.listen(1)

    print("Server listening...\n")
    p = 99528000845113977179280135057556905445364418460826661982741434394774395393367324563030454584752587607511502113473812008131604852272676860461074485154027132234876993823920874230010494656744070000804627484670339786102172175914015562487487183492371859771638039321912946168185032677657470918465203409563666204943
    q = 1367618368300435700925816255674517577959885975497
    while True:
        connection,client = sock.accept()
        print("Connection established from "+str(client))
        try:
                    g = generate_g(p,q)
                    x, y = generate_keys(g, p, q)
                    text = "Hello World, i want to sign this message"
                    M = str.encode(text, "ascii")
                    r, s = sign(M, p, q, g, x)
                    msg = [M,r,s,y]
                    data_string = pickle.dumps(msg,-1)
                    print(msg)
                    connection.send(data_string)
        finally:
            connection.close()
