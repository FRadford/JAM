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

        # "Private" variables set by properties
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
        """
        Helper to generate a new prime and reset root so that it will be calculated on the next access
        """
        if n_bits is not None:
            self.n_bits = n_bits
        self._prime = self._generate_prime()
        self._root = None

    def _generate_prime(self) -> int:
        """
        Helper function to generate a prime number from the instance variable n_bits, raises an error if this is not
        set. n_bits is either set when an instance is initialized or when a prime is loaded from binary data.
        """
        if self.n_bits is None:
            raise ValueError("n_bits is not specified, cannot generate prime. Either specify n_bits or use read "
                             "function to import prime from file")
        print(f"Generating prime with {self.n_bits} bits...")
        return number.getPrime(self.n_bits)

    def _generate_root(self) -> int:
        """
        Helper function to calculate the smallest primitive root modulo n where n is the prime specified on the instance
        """
        print(f"Calculating smallest primitive root modulo n where n = {self._prime}")
        return primitive_root(self._prime)

    def export(self, **kwargs):
        """
        Pickle and write data to file specified on the instance

        To be properly loaded back kwargs must contain at least the _prime and _root variables under the keys 'prime'
        and 'root' respectively
        """
        with open(self.filename, mode="wb") as file:
            pickle.dump(kwargs, file)

    def read(self):
        """
        Un-Pickle data saved in file and load instance variables

        Pickled data must be a dictionary with keys "prime" and "root"
        """
        with open(self.filename, mode="rb") as file:
            data = pickle.load(file)
            try:
                self._prime = data["prime"]
                self._root = data["root"]
            except AttributeError:
                raise AttributeError("File must contain a dictionary with at least keys \"prime\" and \"root\"")
