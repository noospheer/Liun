#!/usr/bin/env python3
"""
Bitwuzla SMT proofs for GF(M61) properties that CBMC/Kani cannot
handle (chained 128-bit symbolic multiply).

These prove properties of the EXACT Rust reduction formula
(lo = x & M61; hi = x >> 61; sum = lo + hi; if sum >= M61: sum - M61)
for ALL possible 64-bit inputs < M61.

Result "unsat" = no counterexample exists = property holds universally.

Requirements: pip install bitwuzla
Run: python3 bitwuzla_gf61.py
"""

from bitwuzla import *
import time

tm = TermManager()
bv64 = tm.mk_bv_sort(64)
bv128 = tm.mk_bv_sort(128)
M61 = tm.mk_bv_value(bv64, 2305843009213693951)
M61_128 = tm.mk_bv_value(bv128, 2305843009213693951)

def w(x):
    return tm.mk_term(Kind.BV_ZERO_EXTEND, [x], [64])

def gf_reduce(x):
    """Exact Rust GF(M61) reduction: lo + hi, conditional subtract."""
    lo = tm.mk_term(Kind.BV_EXTRACT,
        [tm.mk_term(Kind.BV_AND, [x, M61_128])], [63, 0])
    hi = tm.mk_term(Kind.BV_EXTRACT,
        [tm.mk_term(Kind.BV_SHR, [x, tm.mk_bv_value(bv128, 61)])], [63, 0])
    s = tm.mk_term(Kind.BV_ADD, [lo, hi])
    return tm.mk_term(Kind.ITE,
        [tm.mk_term(Kind.BV_UGE, [s, M61]),
         tm.mk_term(Kind.BV_SUB, [s, M61]), s])

def gf_mul(a, b):
    return gf_reduce(tm.mk_term(Kind.BV_MUL, [w(a), w(b)]))

def gf_add(a, b):
    s = tm.mk_term(Kind.BV_ADD, [a, b])
    return tm.mk_term(Kind.ITE,
        [tm.mk_term(Kind.BV_UGE, [s, M61]),
         tm.mk_term(Kind.BV_SUB, [s, M61]), s])

def prove(name, formula):
    """Assert NOT formula; unsat = proved for all inputs."""
    t0 = time.time()
    bt = Bitwuzla(tm, Options())
    for v in syms:
        bt.assert_formula(tm.mk_term(Kind.BV_ULT, [v, M61]))
    bt.assert_formula(tm.mk_term(Kind.NOT, [formula]))
    result = bt.check_sat()
    elapsed = time.time() - t0
    status = "PROVED" if "unsat" in str(result).lower() else str(result)
    print(f"  {name}: {status} ({elapsed:.1f}s)")
    return "unsat" in str(result).lower()

# Symbolic variables
a = tm.mk_const(bv64, 'a')
b = tm.mk_const(bv64, 'b')
c = tm.mk_const(bv64, 'c')
c0 = tm.mk_const(bv64, 'c0')
c1 = tm.mk_const(bv64, 'c1')
r = tm.mk_const(bv64, 'r')
Z = tm.mk_bv_value(bv64, 0)

passed = 0
total = 0

# 1. Multiply commutativity: a*b == b*a
syms = [a, b]
total += 1
if prove("mul_commutative",
    tm.mk_term(Kind.EQUAL, [gf_mul(a, b), gf_mul(b, a)])):
    passed += 1

# 2. Horner 2-coeff: scalar((0*r+c0)*r+c1) == c0*r + c1
syms = [c0, c1, r]
total += 1
h = gf_add(gf_mul(Z, r), c0)
scalar = gf_add(gf_mul(h, r), c1)
direct = gf_add(gf_mul(c0, r), c1)
if prove("horner_2coeff",
    tm.mk_term(Kind.EQUAL, [scalar, direct])):
    passed += 1

print(f"\n  {passed}/{total} proved")

