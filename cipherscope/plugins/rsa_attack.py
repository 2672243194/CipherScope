"""RSA 攻击模块 (v0.2)。

与 bytes 管道插件不同, RSA 攻击通过 CLI 专用命令触发(参数为 n/e/c 整数),
此处提供攻击函数集; RsaPlugin 仅为注册表占位(match 恒为 0)。

已实现攻击:
- small_n_factor: 小模数本地分解 (sympy.factorint, 限 ≤128 bit 防卡死);
- low_exponent: 低加密指数 (e≤7 且 m^e < n, 整数 e 次根直接开方);
- common_modulus: 共模攻击 (同 n 不同 e, 扩展欧几里得);
- wiener: 维纳攻击 (私钥 d 过小时连分数恢复);
- gcd_shared: 多组 n 求公约数 (实现糟糕密钥生成的经典漏洞)。

大整数运算全部纯 Python 实现(math.isqrt / 手写连分数), 不强制 gmpy2;
sympy 仅用于小 n 分解, 缺失时该攻击自动跳过。
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterator

from cipherscope.core.plugin import Candidate


# ------------------------------------------------------------ 数学工具

def integer_nth_root(m: int, e: int) -> tuple[int, bool]:
    """返回 (floor(m 的 e 次根), 是否恰好整除)。"""
    if m < 0 or e <= 0:
        return 0, False
    lo, hi = 0, 1 << (m.bit_length() // e + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** e <= m:
            lo = mid
        else:
            hi = mid - 1
    return lo, lo ** e == m


def int_to_bytes(m: int) -> bytes:
    length = (m.bit_length() + 7) // 8
    return m.to_bytes(length, "big")


def _continued_fraction_convergents(num: int, den: int) -> Iterator[tuple[int, int]]:
    """num/den 连分数展开的渐进分数 (k, d) 序列。"""
    p0, p1, q0, q1 = 0, 1, 1, 0
    while den:
        a = num // den
        p0, p1 = p1, a * p1 + p0
        q0, q1 = q1, a * q1 + q0
        yield p1, q1          # k/d 候选
        num, den = den, num - a * den


# ------------------------------------------------------------ 攻击实现

def small_n_factor(n: int, max_bits: int = 128) -> tuple[int, int] | None:
    """小模数分解。返回 (p, q) 或 None。"""
    if n.bit_length() > max_bits:
        return None
    try:
        from sympy import factorint
    except ImportError:
        return None
    factors = factorint(n)
    primes = list(factors.keys())
    if len(primes) == 2:
        return primes[0], primes[1]
    if len(primes) == 1 and factors[primes[0]] == 2:
        p = primes[0]
        return p, p
    return None


def low_exponent(e: int, c: int, n: int) -> bytes | None:
    """e 小且 m^e < n 时, 直接对 c 开 e 次根。"""
    if e > 7:
        return None
    root, exact = integer_nth_root(c, e)
    return int_to_bytes(root) if exact else None


def common_modulus(n: int, e1: int, c1: int, e2: int, c2: int) -> bytes | None:
    """共模攻击: gcd(e1,e2)=1 时, m = c1^a * c2^b mod n (a*e1+b*e2=1)。"""
    g, a, b = _extended_gcd(e1, e2)
    if g != 1:
        return None
    if a < 0:
        c1 = pow(c1, -1, n)
        a = -a
    if b < 0:
        c2 = pow(c2, -1, n)
        b = -b
    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return int_to_bytes(m)


def _extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = _extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def wiener(e: int, n: int) -> int | None:
    """维纳攻击: d < (1/3)*n^(1/4) 时从 e/n 的连分数恢复 d。"""
    for k, d in _continued_fraction_convergents(e, n):
        if k == 0 or (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1                    # p + q
        disc = s * s - 4 * n               # (p-q)^2
        if disc < 0:
            continue
        r = math.isqrt(disc)
        if r * r == disc and (s + r) % 2 == 0:
            return d
    return None


def gcd_shared(moduli: list[int]) -> list[tuple[int, int, int]]:
    """多组 n 两两求 gcd。返回 [(i, j, p)] 命中列表。"""
    hits = []
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            p = math.gcd(moduli[i], moduli[j])
            if 1 < p < min(moduli[i], moduli[j]):
                hits.append((i, j, p))
    return hits


def decrypt_with_factor(c: int, n: int, p: int, e: int) -> bytes | None:
    """已知一个因子时完整解密。e 与 φ(n) 不互素(非法公钥)时返回 None。"""
    q = n // p
    phi = (p - 1) * (q - 1)
    try:
        d = pow(e, -1, phi)
    except ValueError:
        return None   # e 与 φ(n) 不互素, 不是合法 RSA 公钥
    return int_to_bytes(pow(c, d, n))


def solve_d(p: int, q: int, e: int) -> int | None:
    """已知 p/q/e 求私钥指数 d = e⁻¹ mod φ(n)。CTF 高频题型
    (题目直接给 p、q、e, 求 d 提交为 flag)。e 与 φ(n) 不互素时返回 None。"""
    phi = (p - 1) * (q - 1)
    try:
        return pow(e, -1, phi)
    except ValueError:
        return None   # gcd(e, φ(n)) != 1, 非法公钥


def solve_plaintext(p: int, q: int, e: int, c: int) -> bytes | None:
    """已知 p/q/e/c 直接解明文 (babyRSA 最基础题型):
    d = e⁻¹ mod φ(n), m = c^d mod n。非法公钥返回 None。"""
    d = solve_d(p, q, e)
    if d is None:
        return None
    return int_to_bytes(pow(c, d, p * q))


def fermat_factor(n: int, max_iter: int = 200_000) -> tuple[int, int] | None:
    """费马分解: p 与 q 很接近时 (p = nextprime(q) 等), 从 isqrt(n) 递增 a,
    检查 a² - n 是否为完全平方数。返回 (p, q) 或 None。"""
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2 and b > 0:
            p, q = a + b, a - b
            if 1 < q < n:
                return min(p, q), max(p, q)
        a += 1
    return None


def pollard_p1(n: int, bound: int = 50_000) -> int | None:
    """Pollard p-1 分解: 当 p-1 或 q-1 是 B-smooth(B=bound) 时,
    从 a=2 迭代 a = a^i mod n, 检查 gcd(a-1, n) 得到因子。"""
    a = 2
    for i in range(2, bound):
        a = pow(a, i, n)
        g = math.gcd(a - 1, n)
        if 1 < g < n:
            return g
    return None


def dp_leak(dp: int, n: int, e: int, c: int) -> bytes | None:
    """dp 泄露攻击: 已知 dp = d mod (p-1), 恢复 p 后解密。
    k = e*dp - 1 是 (p-1) 的倍数, 遍历 x | k 检验 p = k//x + 1 是否整除 n。"""
    k = e * dp - 1
    for x in range(1, e + 1):
        if k % x:
            continue
        p = k // x + 1
        if p > 1 and n % p == 0:
            q = n // p
            d = solve_d(p, q, e)
            if d is None:
                return None
            return int_to_bytes(pow(c, d, n))
    return None


def hastad_broadcast(e: int, ns: list[int], cs: list[int]) -> bytes | None:
    """低加密指数广播攻击 (Håstad): 同一明文 m 用同一 e 加密为多组 (n_i, c_i),
    且 m^e < ∏n_i 时, CRT 合并 M = m^e mod ∏n_i, 再开 e 次根得 m。
    要求 n_i 两两互素且组数 >= e。"""
    if len(ns) < e or len(ns) != len(cs):
        return None
    # CRT 合并
    prod = 1
    for n_i in ns:
        prod *= n_i
    m_e = 0
    for n_i, c_i in zip(ns, cs):
        ni = prod // n_i
        try:
            inv = pow(ni, -1, n_i)
        except ValueError:
            return None   # n_i 不互素, 广播前提不成立
        m_e = (m_e + c_i * ni * inv) % prod
    root, exact = integer_nth_root(m_e, e)
    return int_to_bytes(root) if exact else None


# ------------------------------------------------------------ 注册表占位

class RsaPlugin:
    """注册表占位: RSA 攻击经 CLI `cipherscope rsa` 触发, 不走 bytes 管道。"""

    name = "rsa"
    category = "rsa"

    def match(self, ct: bytes) -> float:
        return 0.0

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        return
        yield  # pragma: no cover


ALL_RSA = [RsaPlugin()]
