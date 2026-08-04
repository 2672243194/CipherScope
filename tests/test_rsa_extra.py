"""RSA 新题型单测: p/q/e/c 解明文 / 费马 / Pollard p-1 / dp泄露 / 低指数广播。"""
import math

import pytest
import sympy

from cipherscope.plugins import rsa_attack as R


def _lt(m: int) -> bytes:
    return m.to_bytes((m.bit_length() + 7) // 8, "big")


def test_solve_plaintext_direct():
    p, q, e = 473398607161, 4511491, 17
    m = int.from_bytes(b"RSA!", "big")
    c = pow(m, e, p * q)
    assert R.solve_plaintext(p, q, e, c) == b"RSA!"


def test_solve_plaintext_invalid_key():
    # e=4 与 φ(n) 不互素
    assert R.solve_plaintext(5, 7, 4, 123) is None


def test_fermat_close_primes():
    p = sympy.nextprime(2**64)
    q = sympy.nextprime(p)
    assert R.fermat_factor(p * q) == (min(p, q), max(p, q))


def test_fermat_fails_random():
    # 距离远的素数, 费马在迭代上限内失败
    p = sympy.nextprime(2**64)
    q = sympy.nextprime(2**96 + 12345)
    assert R.fermat_factor(p * q, max_iter=2000) is None


def test_pollard_p1_smooth():
    smooth = 1
    for pr in [2, 3, 5, 7, 11, 13, 17, 19, 23]:
        smooth *= pr
    p = smooth + 1
    while not sympy.isprime(p):
        smooth *= 2
        p = smooth + 1
    q = sympy.nextprime(2**60 + 7)
    assert R.pollard_p1(p * q, bound=1000) == p


def test_dp_leak():
    e = 17
    p, q = sympy.nextprime(2**40), sympy.nextprime(2**41)
    n = p * q
    d = pow(e, -1, (p - 1) * (q - 1))
    dp = d % (p - 1)
    m = int.from_bytes(b"flag{dp}", "big")
    c = pow(m, e, n)
    assert R.dp_leak(dp, n, e, c) == b"flag{dp}"


def test_hastad_broadcast():
    m = int.from_bytes(b"flag_bcast", "big")
    ns, cs = [], []
    for i in range(3):
        pn, qn = sympy.nextprime(2**64 + i * 10**12), sympy.nextprime(2**66 + i * 10**12)
        ns.append(pn * qn)
        cs.append(pow(m, 3, pn * qn))
    assert R.hastad_broadcast(3, ns, cs) == b"flag_bcast"


def test_hastad_needs_coprime_moduli():
    # n_i 不互素时返回 None 而非崩溃
    n = 3233 * 17
    assert R.hastad_broadcast(3, [n, n, n], [1, 2, 3]) is None


def test_integer_nth_root_exact_and_floor():
    assert R.integer_nth_root(27, 3) == (3, True)
    assert R.integer_nth_root(28, 3) == (3, False)
