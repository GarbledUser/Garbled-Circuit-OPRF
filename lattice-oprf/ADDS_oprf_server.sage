import chunk
from datetime import date, datetime
from email import message
from mimetypes import init
from pickle import dumps, loads
import time
import socketserver

"""
A very rough (!) proof of concept implementation .
"""
from sage.all import matrix, vector
from sage.all import ceil, log, xgcd, next_prime, inverse_mod
from sage.all import ZZ, QQ, IntegerModRing
#from sage.misc.persist import SagePickler

class VOPRFPoC (object):
    """
    Figure 2
    """
    def __init__ (self, n, p, q):
        """
        Setup
        : param n : ring dimension, must be power of two
        : param p : rounding modulus
        : param q : computation modulus
        """
        self.q = q
        self.p = p
        self.n = n
        self.ell = ceil(log(q,2))

        # NOTE : we do modular reductions mod phi = X ^ n +1 hand
        self.R_Z = ZZ ["x"]
        self.X = self.R_Z.gen()
        self.phi = self.X**n + 1
        self.R = IntegerModRing(q)["x"]
        self.a = [vector (self.R, self.ell,[self.R.random_element (degree = n - 1) for _ in range (self.ell)],) for _ in range (3)]
        self.k = self.sample_small()
        self.c = self.a[2] * self.k + self.sample_small (scalar = False) # a [2] == a in Figure 2

    def bp14 (self, x, k =1):
        """
        Evaluate BP14 on input x and key k
        : param x : a vector of bits
        : param k : a small element in R
        """
        L = len(x)
        t = 1
        for i in range (1, L)[:: -1]:
            t = self.ginv(self.modred(self.a[x[i]] * t))
        ax = self.modred(self.a[x[0]] * t)
        e = self.sample_small(scalar = False)
        return self.modred(ax * k) + e

    def sample_small (self, bound =1, scalar = True):
        """
        Sample a small element in R or R ^ l
        : param bound : l_oo bound on coefficients
        : param scalar : if True return element in R, otherwise in R ^ l
        """
        if scalar :
            return self.R_Z.random_element (degree = self.n - 1, x = - bound, y = bound + 1)
        else :
            return vector (self.R_Z, self.ell, [self.sample_small () for _ in range (self.ell)],)

    def modred(self, v):
        """
        Reduce an element in R ^ l modulo phi
        : param v : an element in R ^ l
        """
        return vector(self.R, self.ell, [v_ % self.phi for v_ in v ])

    def nice_lift(self, h):
        """
        Return a balanced integer representation of an element in R .
        : param h : an element in R
        """
        r = []
        h = h % self.phi
        for e in h :
            if ZZ(e) > self.q // 2:
                r.append (ZZ (e) - self.q)
            else :
                r.append (ZZ (e))
        return self.R_Z (r)

    def ginv (self, a):
        """
        Return G^-1(a), i.e.bit decomposition .
        : param a : an element in R^l
        """
        A = matrix(self.R, self.ell, self.ell)
        for i in range(self.ell):
            a_ = a[i]. change_ring(ZZ)
            for j in range (self.ell):
                A[j, i] = self.R(
                    [(ZZ(a__) // 2**j) % 2 for a__ in a_ ]
               )
        assert self.G * A == a
        return A

    @property
    def G (self):
        """
        Vector G = [1,2,4,...] in R ^ l
        """
        return vector(
                self.R, self.ell, [2**i for i in range(self.ell)]
       )

    def __call__ (self, x):
        """
        Run the protocol on x, ignoring zero - knowledge proofs
        : param x : a vector of bits
        """
        # CLIENT
        s = self.sample_small(scalar = True)
        e1 = self.sample_small(scalar = False)
        cx = self.bp14(x) + self.a[2] * s + e1
        # SERVER
        e_ = self.sample_small(bound =2**64, scalar = False)
        dx = self.modred(cx * self.k + e_)
        # CLIENT
        y = self.nice_lift((dx - self.c * s)[0])
        return y // (self.q / self.p)

class AltVOPRFPoC (VOPRFPoC):
    """
    """

    def __init__ (self, n, p, q):
        """
        Setup
        : param n : ring dimension, must be power of two
        : param p : rounding modulus
        : param q : computation modulus
        """
        self.q = q
        self.p = p
        self.n = n
        self.ell = ceil(log(q,2))
        # NOTE : we do modular reductions mod phi = X ^ n +1 hand
        self.R_Z = ZZ["x"]
        self.X = self.R_Z.gen()
        self.phi = self.X**n + 1
        self.R = IntegerModRing(q)["x"]
        self.a = [
            vector (
                self.R,
                self.ell,
                [
                    self.R.random_element(degree = n - 1)
                    for _ in range(self.ell)
                ],
           )
            for _ in range(2)
        ]
        self.k = self.sample_small()

def full_ntru (self, s, t):
    """
    Return small u,v  s.t. u * s + v * t = 1
    : param s : a small element in R
    : param t : a small element in R
    """
    Rs = s.resultant(self.phi)
    Rt = t.resultant(self.phi)
    u_ = (Rs * s.change_ring(QQ).inverse_mod(self.phi)) % self.phi
    v_ = (Rt * t.change_ring(QQ).inverse_mod(self.phi)) % self.phi
    r, u__, v__ = xgcd(Rs, Rt)
    u = u__ * u_
    v = v__ * v_
    u = u.change_ring(ZZ)
    v = v.change_ring(ZZ)

    def conjugate (f):
        ft = -f[self.n // 2] * self.X**(self.n // 2) + f[0]
        for i in range (1, self.n // 2):
            ft += (
                -f [ i ] * self.X ** (self.n - i)
                - f [ self.n - i ] * self.X ** i
           )
        return ft

    def xgcd_reduce (f, g, G, F):
        """
        https :// eprint.iacr.org /2019/015 solves f * G ' - g * F ' == f * G - g * F
        We map s,t,u, v to f,g, -G, F .
        """
        f, g, F, G = f, g, F, -G
        for j in range (32):
            num = (F * conjugate(f) + G * conjugate(g)) % self.phi
            den = (f * conjugate(f) + g * conjugate(g)) % self.phi
            k = (
                num
                * inverse_mod(den.change_ring(QQ), self.phi)
                % self.phi
            )
            k = sum (
                [
                    round(c) * self.X**i
                    for i, c in enumerate(list(k))
                ]
            )
            if k == 0:
                break
            F, G = (F - k * f) % self.phi, (G - k * g) % self.phi
        return -G, F

    u, v = xgcd_reduce (s, t, u, v)
    return u, v

def __call__ (self, x):
    """
    Run the protocol on x, ignoring zero - knowledge proofs
    : param x : a vector of bits
    """
    # CLIENT
    while True:
        s = self.sample_small()
        t = self.sample_small()
        u, v = self.full_ntru(s, t)
        if (u * s + v * t) % self.phi == 1:
            break
    c1 = self.bp14(x, s)
    c2 = self.bp14(x, t)
    # SERVER
    d1 = self.modred(
        c1 * self.k + self.sample_small(bound =2**64, scalar = False)
    ) # for " drowning "
    d2 = self.modred (
        c2 * self.k + self.sample_small(bound =2**64, scalar = False)
    )
    # CLIENT
    yx = self.nice_lift((u * d1 + v * d2)[0])
    return yx // (self.q / self.p)

# Taken from https://stackoverflow.com/questions/34653875/python-how-to-send-data-over-tcp
class MyTCPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        print('handle request...')
        # self.request is the TCP socket connected to the client
        #self.data = self.request.recv(1024).strip()
        cx_bytes = b''
        expected_size = self.request.recv(8)
        count = int.from_bytes(expected_size, 'big')
        print("waiting for " + str(count) + " bytes")
        while count > 0:
            print(count)
            chunk = self.request.recv(512)
            cx_bytes += chunk
            count -= len(chunk)
        print("size received = " + str(len(cx_bytes)))
        answer = voprfServer(cx_bytes)
        self.request.sendall(len(answer).to_bytes(8, 'big') + answer)


# instantiate with some toy parameters
#def test (cls = VOPRFPoC, p = 3, q_size =96, n =256):
def voprfServer (msg):
    print("Process request...")
    cls = VOPRFPoC; p = 3; q_size = 96; n = 256
    q_ = next_prime (2 ** q_size)
    voprf = cls(n, p, p * q_)

    cx = loads(msg)
    e_ = voprf.sample_small(bound =2**64, scalar = False)
    dx = voprf.modred(cx * voprf.k + e_)
    return dumps(dx)


def main(port):
    HOST, PORT = '127.0.0.1', int(port)
    server = socketserver.TCPServer((HOST, PORT), MyTCPHandler)
    server.serve_forever()

if __name__ == "__main__":
    main(sys.argv[1])

