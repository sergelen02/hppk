# HPPK-DS algorithm trace

This document is the implementation ledger. Every production function must be
mapped to the exact corresponding equation and line of Algorithms 1--6 in the
paper before its performance is measured.

| Paper algorithm | Repository function | Status | Test evidence |
|---|---|---|---|
| Algorithm 1 | hppkdsref.KeyGen | pending | golden vector |
| Algorithm 2--5 | helper functions | pending | unit tests |
| Algorithm 6 | hppkdsref.Verify | pending | valid + negative vectors |

The NoBarrett package is a separate ablation. It is not evidence that the
paper-reference construction is implemented or secure.
