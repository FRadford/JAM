import argparse

import Util

parser = argparse.ArgumentParser(prog="generate-prime")
parser.add_argument("-n", "--n_bits", type=int, default=4096,
                    help="Length of generated prime in bits. Recommended to be at least 2048, defaults to 4096")
parser.add_argument("-f", "--file", type=str, default="prime.dmp", help="Name of dump file, defaults to prime.dmp")

args = parser.parse_args()

prime = Util.prime_helper.PrimeHelper("prime.dmp", args.n_bits)
prime.export(prime=prime.prime, root=prime.root)
