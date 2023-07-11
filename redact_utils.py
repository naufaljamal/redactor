from __future__ import absolute_import
import json
import os
import hashlib
import yaml
import binascii
from Cryptodome.Cipher import AES
from functools import lru_cache
from redact_exceptions import YAMLNotFoundException, BadDataException, InvalidFileStructureException, BadAESKeyException, AESKeyMismatch


@lru_cache(maxsize=32)
def get_nonce(aes_key: str):
    """
    Get a nonce value for the given AES key.

    Args:
        aes_key (str): AES key for nonce generation.

    Returns:
        bytes: Nonce value.

    """
    return generate_nonce()


def generate_nonce():
    """ Generates a random nonce for AES encryption """
    nonce_size = 32  # 96 bits is commonly used for AES-GCM
    return os.urandom(nonce_size)


def validate_aes_key(aes_key):
    """
    Validates if a given AES key is 32 bytes (256 bits) long.

    Args:
        aes_key (str): The AES key to validate.

    Returns:
        bool: True if the AES key is 32 bytes long, False otherwise.

    """
    return len(aes_key) == 32


def encrypt(plaintext, aes_key):
    """
    Encrypt a plaintext secret with the AES key.

    Args:
        plaintext (str): Plaintext secret to encrypt.
        aes_key (str): AES key for encryption.

    Returns:
        str: Hexadecimal representation of the ciphertext.

    """
    if not validate_aes_key(aes_key):
        raise BadAESKeyException("Invalid AES key provided. Key needs to be 32 bit!")
    nonce = get_nonce(aes_key)
    encobj = AES.new(aes_key.encode("utf8"), AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = encobj.encrypt_and_digest(plaintext.encode("utf8"))
    return (ciphertext + tag).hex()


def decrypt(encrypted_text, aes_key):
    """
    Decrypt a ciphertext with the AES key.

    Args:
        encrypted_text (str): Ciphertext to decrypt in hexadecimal representation.
        aes_key (str): AES key for decryption.

    Returns:
        str: Decrypted original plaintext.

    """
    try:
        data = binascii.unhexlify(encrypted_text)
        (encrypted_text, tag) = data[0:-16], data[-16:]
        encobj = AES.new(aes_key.encode("utf8"), AES.MODE_GCM, nonce=get_nonce(aes_key))
        return encobj.decrypt_and_verify(encrypted_text, tag)
    except ValueError:
        raise AESKeyMismatch("AES key mismatch. Use the same key used in Encryption!")


def read_yaml(file_path):
    """
    Read and validate a YAML file containing secrets.

    Args:
        file_path (str): Path to the YAML file.

    Returns:
        dict: Dictionary containing the secrets.

    Raises:
        YAMLNotFoundException: If the YAML file is not found.
        InvalidFileStructureException: If the YAML structure is not a dictionary.
        BadDataException: If the required keys or values are missing or have invalid formats.
    """

    # Check if the yaml file is present or not
    if not file_path:
        return None

    if not os.path.exists(file_path):
        raise YAMLNotFoundException("No yaml file found!")

    # Check if the yaml file is a dict and has the keys "secrets" in it
    yaml_content = yaml.safe_load(open(file_path))
    if not isinstance(yaml_content, dict):
        raise InvalidFileStructureException("Invalid yaml structure found! Yaml data needs to be a dict")
    if 'secrets' not in yaml_content:
        raise BadDataException("'secrets' key not found in yaml provided!")

    # Check if the values under "secrets" are lists of integers
    keys = yaml_content['secrets'].keys()
    for key in keys:
        if not isinstance(yaml_content['secrets'][key], list):
            raise BadDataException("{} needs to be a list".format(yaml_content['secrets'][key]))
        for item in yaml_content['secrets'][key]:
            if not isinstance(item, int):
                raise BadDataException("{} needs to be in integer format!".format(item))

    return yaml_content['secrets']


def encrypt_text(text, aes_key, data):
    """
        args: 
            text: text data to be encrypted
            aes_key: AES encryption key
            data: yaml data with strings and indexes
        
        returns:
            encrypted_text: Encrypted text output
        
        * Split the text into individual words using split().
        * Iterate over each key and indexes pair in the data dictionary.
        * For each key, iterate over the words in the words list.
        * If a word matches the key, iterate over the indexes.
        * Calculate the index of the word to encrypt.
        * Check if the word is not the same as the key and does not already contain @encrypted_.
        * If the conditions are met, encrypt the word and prepend it with @encrypted_.
        * Replace the original word with the encrypted word in the words list.
        * Join the modified words list back into a string using ' '.join() to form the encrypted text.
        * Return the encrypted text.
    """
    if data is None:
        # Encrypt the whole text and prepend "@encrypted_"
        encrypted_text = "@encrypted_{}".format(encrypt(text, aes_key))
        return encrypted_text

    words = text.split()
    for key, indexes in data.items():
        for _i in range(len(words) - 1):
            # Check if the current word matches the key
            if words[_i] == key:
                for index in indexes:
                    # Calculate the index of the word to encrypt
                    word_index = _i + 1 + index
                    # Ensure the word index is within the word list bounds
                    if word_index < len(words):
                        word = words[word_index]
                        # Check if the word is not the same as the key and doesn't already contain "@encrypted_"
                        if word != key and "@encrypted_" not in word:
                            # Encrypt the word and prepend it with "@encrypted_"
                            encrypted_word = "@encrypted_{}".format(encrypt(word, aes_key))
                            # Replace the original word with the encrypted word
                            words[word_index] = encrypted_word
    # Join the modified words back into a string to form the encrypted text
    encrypted_text = ' '.join(words)

    return encrypted_text



def decrypt_text(encrypted_text, aes_key):
    """
    Decrypt an encrypted text containing marked words.

    Args:
        encrypted_text (str): Encrypted text to decrypt.
        aes_key (str): AES key for decryption.

    Returns:
        str: Decrypted text with marked words replaced.

    * Split the encrypted text into individual words.
    * Iterate over each word in the text.
    * Check if a word starts with the marker @encrypted_, indicating it is an encrypted word.
    * If an encrypted word is found, extract the encrypted part by removing the @encrypted_ prefix.
    * Decrypt the extracted encrypted word using the provided AES key.
    * Decode the decrypted word from bytes to a string.
    * Replace the original encrypted word with the decrypted word in the list of words.
    * Join the modified words back into a string, using spaces as separators, to form the decrypted text.
    * Return the decrypted text.
    """
    words = encrypted_text.split()
    for index in range(len(words)):
        word = words[index]
        if word.startswith("@encrypted_"):
            encrypted_word = word[len("@encrypted_"):]
            decrypted_word = decrypt(encrypted_word, aes_key).decode()  # Decode bytes to string
            words[index] = decrypted_word
    decrypted_text = ' '.join(words)
    return decrypted_text
