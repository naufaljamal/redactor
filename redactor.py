import redact_utils as utils

class Encrypt(object):
    """
    Encrypts the given plaintext using the provided AES key and YAML file.

    Args:
        plaintext (str): The plaintext to be encrypted.
        aes_key (str): The AES key used for encryption.
        file_path (str): The path to the YAML file containing encryption configuration.

    """
    def __init__(self, plaintext, aes_key, file_path):
        self.plaintext = plaintext
        self.aes_key = aes_key
        self.file_path = file_path
    
    def encrypt(self):
        """
        Encrypts the plaintext using the AES key and YAML configuration.

        Returns:
            str: The encrypted text.

        """
        self.yaml_data = utils.read_yaml(self.file_path)
        return utils.encrypt_text(self.plaintext, self.aes_key, self.yaml_data)


class Decrypt(object):
    """
    Decrypts the given encrypted text using the provided AES key.

    Args:
        encrypted_text (str): The encrypted text to be decrypted.
        aes_key (str): The AES key used for decryption.

    """
    def __init__(self, encrypted_text, aes_key):
        self.encrypted_text = encrypted_text
        self.aes_key = aes_key

    def decrypt(self):
        """
        Decrypts the encrypted text using the AES key.

        Returns:
            str: The decrypted plaintext.

        """
        return utils.decrypt_text(self.encrypted_text, self.aes_key)
