from Cryptodome.Cipher import AES
from Cryptodome.Util import Padding


class Message(object):
    """
    Stores message information, ready for pickling
    """

    def __init__(self, text, recipient=None):
        self.text = text
        self.recipient = recipient


class EncryptedMessage(Message):
    """
    Encrypted message information, ready for pickling
    """

    def __init__(self, key: bytes, text: str, tag: bytes = None, nonce: bytes = None, recipient=None):
        super(EncryptedMessage, self).__init__(text, recipient)
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