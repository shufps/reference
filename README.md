Changed Troika for SIMD calculations. Calculates 32, 64, 128 (SSE) or 256 (AVX) hashs in parallel.

Main application is for "batch-processing" a lot of hashes.

Single-hashing performance is slow, though.

For single-hashing the best Troika is f-troika: https://github.com/c-mnd/troika

Original README:

# Troika

This repository contains the reference implementation of the Troika hash
function. Troika is a cryptographic hash function operating on ternary messages
for the use in IOTA’s distributed ledger technology designed. 

For further information see the [Troika website](https://www.cyber-crypt.com/troika).
