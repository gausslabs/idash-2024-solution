# RESIDUAL PARAMETERS SECURITY

```python
from estimator import *

n = 1<<15
q = 1<<819
Xs = ND.SparseTernary(n, p=96, m=96)
Xe = ND.DiscreteGaussian(3.2)

LWE.estimate(LWE.Parameters(n=n, q=q, Xs=Xs, Xe=Xe, m=2*n), red_cost_model = RC.BDGL16)

arora-gb             :: rop: ≈2^inf, m: ≈2^inf, dreg: 615, t: 16, mem: ≈2^inf, tag: arora-gb, ↻: ≈2^inf, ζ: ≈2^15.0, |S|: ≈2^16.0, prop: ≈2^-1074.0
usvp                 :: rop: ≈2^138.1, red: ≈2^138.1, δ: 1.004348, β: 352, d: 63075, tag: usvp
bdd                  :: rop: ≈2^138.0, red: ≈2^137.9, svp: ≈2^133.8, β: 351, η: 402, d: 65063, tag: bdd
bdd_hybrid           :: rop: ≈2^133.5, red: ≈2^133.4, svp: ≈2^128.9, β: 317, η: 2, ζ: ≈2^11.2, |S|: ≈2^91.6, d: 60810, prob: 0.092, ↻: 48, tag: hybrid
bdd_mitm_hybrid      :: rop: ≈2^128.5, red: ≈2^128.3, svp: ≈2^125.7, β: 303, η: 2, ζ: ≈2^11.9, |S|: ≈2^178.9, d: 58553, prob: 0.175, ↻: 24, tag: hybrid
dual                 :: rop: ≈2^138.2, mem: ≈2^81.5, m: ≈2^15.0, β: 352, d: 65265, ↻: 1, tag: dual
dual_hybrid          :: rop: ≈2^137.6, red: ≈2^137.6, guess: ≈2^127.8, β: 350, p: 2, ζ: 0, t: 110, β: 350, N: ≈2^71.8, m: ≈2^15.0
```

# BOOTSTRAPING PARAMETERS SECURITY

```python
from estimator import *

n = 1<<16
q = 1<<1726
Xs = ND.SparseTernary(n, p=160, m=160)
Xe = ND.DiscreteGaussian(3.2)

LWE.estimate(LWE.Parameters(n=n, q=q, Xs=Xs, Xe=Xe, m=2*n), red_cost_model = RC.BDGL16)

arora-gb             :: rop: ≈2^inf, m: ≈2^inf, dreg: ≈2^12.3, t: 17, mem: ≈2^inf, tag: arora-gb, ↻: ≈2^inf, ζ: ≈2^15.9, |S|: ≈2^16.9, prop: ≈2^-1074.0
usvp                 :: rop: ≈2^131.6, red: ≈2^131.6, δ: 1.004580, β: 326, d: 129532, tag: usvp
bdd                  :: rop: ≈2^187.2, red: ≈2^131.3, svp: ≈2^187.2, β: 325, η: 585, d: 130282, tag: bdd
bdd_hybrid           :: rop: ≈2^132.0, red: ≈2^132.0, svp: ≈2^124.0, β: 307, η: 2, ζ: ≈2^11.4, |S|: ≈2^84.2, d: 125618, prob: 0.070, ↻: 64, tag: hybrid
bdd_mitm_hybrid      :: rop: ≈2^128.5, red: ≈2^128.5, svp: ≈2^124.4, β: 312, η: 2, ζ: ≈2^11.4, |S|: ≈2^179.0, d: 126346, prob: 0.919, ↻: 2, tag: hybrid
dual                 :: rop: ≈2^131.9, mem: ≈2^76.2, m: ≈2^16.0, β: 327, d: 130914, ↻: 1, tag: dual
dual_hybrid          :: rop: ≈2^131.6, red: ≈2^131.6, guess: ≈2^117.6, β: 326, p: 2, ζ: 0, t: 100, β: 326, N: ≈2^19.1, m: ≈2^16.0
```