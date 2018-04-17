"""
CLI for generating primes, pickling them and dumping to a binary file in such a way that it can be read by the
client and used during a key exchange. Generating large enough primes (>2048 bits) to be secure is a time consuming
process that would be infeasible to run every time a shared secret is generated.

Exports pickled prime to file specified by user, default: prime.dmp
"""

import argparse

import Util

# CLI setup
parser = argparse.ArgumentParser(prog="generate-prime")
parser.add_argument("-n", "--n_bits", type=int, default=4096,
                    help="Length of generated prime in bits. Recommended to be at least 2048, defaults to 4096")
parser.add_argument("-f", "--file", type=str, default="prime.bin", help="Name of dump file, defaults to prime.bin")

args = parser.parse_args()

# Generate prime
prime = Util.prime_helper.PrimeHelper("prime.bin", args.n_bits)
prime.export(prime=prime.prime, root=prime.root)
