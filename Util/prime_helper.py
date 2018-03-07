import pickle

from Cryptodome.Util import number
from sympy.ntheory.residue_ntheory import primitive_root


class PrimeHelper(object):
    """
    Helper class to manipulate large prime numbers for cryptographic use
    """

    def __init__(self, filename: str, n_bits: int = None):
        self.n_bits = n_bits
        self.filename = filename

        self._prime = None
        self._root = None

    @property
    def prime(self) -> int:
        """
        Generates new _prime if _prime has never been accessed before, always returns _prime.
        """
        if self._prime is None:
            self._prime = self._generate_prime()
        return self._prime

    @property
    def root(self) -> int:
        """
        Calculates smallest primitive root modulo n where n is _prime if _root has never been accessed before or has
        been reset, always returns _root.
        """
        if self._root is None:
            self._root = self._generate_root()
        return self._root

    def new_prime(self, n_bits=None):
        if n_bits is not None:
            self.n_bits = n_bits
        self._prime = self._generate_prime()
        self._root = None

    # Generate new prime of n_bits specified on object
    def _generate_prime(self) -> int:
        if self.n_bits is None:
            raise ValueError("n_bits is not specified, cannot generate prime. Either specify n_bits or use read "
                             "function to import prime from file")
        print(f"Generating prime with {self.n_bits} bits...")
        return number.getPrime(self.n_bits)

    # Generate smallest primitive root modulo n where n is the prime specified on the object
    def _generate_root(self) -> int:
        print(f"Calculating smallest primitive root modulo n where n = {self._prime}")
        return primitive_root(self._prime)

    # Write pickled data to file specified on object
    def export(self, **kwargs):
        with open(self.filename, mode="wb") as file:
            pickle.dump(kwargs, file)

    # Returns un-pickled data from file specified on object
    def read(self):
        with open(self.filename, mode="rb") as file:
            data = pickle.load(file)
            self._prime = data["prime"]
            self._root = data["root"]


if __name__ == "__main__":
    prime = PrimeHelper("prime.dmp", 4096)
    prime.export(prime=prime.prime, root=prime.root)
