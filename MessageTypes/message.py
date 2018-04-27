from Cryptodome.Cipher import AES
from Cryptodome.Util import Padding


class Message(object):
    """
    Stores message information, ready for encoding
    """

    def __init__(self, text: object = None, recipient: str = None, sender: str = None):
        self.text = text
        self.recipient = recipient
        self.sender = sender


class KeyExchangeMessage(Message):
    """
    Stores Key Exchange specific information, ready for encoding
    """

    def __init__(self, request: str, prime: int = None, root: int = None, public: int = None, recipient: str = None,
                 sender: str = None):
        super(KeyExchangeMessage, self).__init__(recipient=recipient, sender=sender)

        self.request = request
        self.prime = prime
        self.root = root
        self.public = public


class EncryptedMessage(Message):
    """
    Encrypted message information, ready for encoding
    """

    def __init__(self, key: bytes, text: str, tag: bytes = None, nonce: bytes = None, recipient: str = None,
                 sender: str = None):
        super(EncryptedMessage, self).__init__(text, recipient, sender)
        self.key = key
        self.tag = tag

        self.nonce = self.set_key(nonce).nonce

        if not nonce:
            self.text, self.tag = self.encrypt()
        else:
            self.text = self.decrypt()

    def set_key(self, nonce: bytes = None) -> AES:
        """
        Helper function to setup cipher

        If nonce is not specified it will be generated by the cipher
        """
        return AES.new(self.key, AES.MODE_EAX, nonce=nonce)

    def encrypt(self) -> (bytes, bytes):
        """
        Encrypts input text with input key and nonce using cipher specified on the instance and generates a tag that
        can be used to verify message integrity

        Returns a tuple with the encrypted text, hash for checking integrity, and nonce
        """

        ciphertext, tag = self.set_key(self.nonce).encrypt_and_digest(Padding.pad(bytes(self.text, "utf-8"), 16))
        return ciphertext, tag

    def decrypt(self) -> str:
        """
        Decrypts encrypted text with cipher specified on the instance and checks tag to verify message integrity
        """

        cipher = self.set_key(self.nonce)

        plaintext = Padding.unpad(cipher.decrypt(self.text), 16)

        # Verify message integrity
        try:
            cipher.verify(self.tag)
        except ValueError:
            raise

        return str(plaintext, "utf-8")


class LoginMessage(Message):
    def __init__(self, key: bytes, username: str, password: str, recipient: str = "root", sender: str = None):
        super(LoginMessage, self).__init__(recipient=recipient, sender=sender)

        self.username = EncryptedMessage(key, username)
        self.password = EncryptedMessage(key, password)


class RegisterMessage(LoginMessage):
    def __init__(self, key: bytes, username: str, password: str, recipient: str = "root", sender: str = None):
        super(RegisterMessage, self).__init__(key, username, password, recipient, sender)
