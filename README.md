# redactor
Secret redaction utility

Redactor is a Python library that provides a mechanism for encrypting sensitive information in text or configurations. It offers an easy-to-use solution for users who want to secure their secrets by encrypting specific keywords or phrases in their data.

# Features
Flexible Encryption: PyPI-Redactor allows users to define keywords in a YAML file and specify the indexes of the words they want to encrypt. It supports customizable encryption using the AES (Advanced Encryption Standard) algorithm.

YAML Configuration: Users can maintain a YAML file where they define the keywords and indexes to be encrypted. This configuration file provides flexibility and ease of use.

Command-line Interface (CLI): Redactor includes a command-line interface that allows users to interactively encrypt or decrypt sensitive information in their text or configurations.

Open Source: Redactor is an open-source project, available on GitHub, and welcomes contributions from the community.

# Yaml File
A sample yaml file can be like this

```
secrets:
  password: [0]
  key: [0, 1]
```
Here you are setting the redaction saying encrypt the 0th indexed value after the keyword "password" so.eg

If the plaintext is "device set password fakepassword" here 0th indexed word after password is "fakepassword" hence that will be encrypted

if the plaintext is "key set fakekey", here 0th and 1st indexed word after key is "set" and "fakekey" hence both will be encrypted.

# AES key
We are using a 32-bit aes key for encryption/decryption of the text data

# Usage

1)
```
plaintext = "the password fake_password secret fake_secret_1 fake_secret_2 three"
aes_key = "asdsed1234dsdsdsds33dsdsdsdsds21"
file_path = "$path_to_yaml file"
```
Yaml Content:
```
cat redactor.yaml
secrets:
  password: [0]
  secret: [0, 1]
```

In this example yaml, you can set the redaction rules by specifying the index positions of the words to be encrypted after each keyword.

```
e = Encrypt(plaintext, aes_key, file_path)
encrypted_text = e.encrypt()
print(encrypted_text)

d = Decrypt(enc_text, aes_key)
print(d.decrypt())
```
would return
```
Encrypted output:
the password @encrypted_9b082d455227c7ca528f6adedcf3bc3a810590d6bf66798c7c8e83a573 secret @encrypted_9b082d455224c3da539d71f389593c1553aeaeeca5ad7236aa885425b7 @encrypted_9b082d455224c3da539d71f38a72d86b89202588e4b56d42f9efff5bba three

Decrypted output:
the password fake_password secret fake_secret_1 fake_secret_2 three
```

The 0th index after word password and 0th/1st index after word secret are redacted


2) If you dont provide a file path, it will encrypt the entire plaintext content. E.g
```
   plaintext = "the password fake_password secret fake_secret_1 fake_secret_2 three"
   aes_key = "asdsed1234dsdsdsds33dsdsdsdsds21"

   enc = Encrypt(plaintext, aes_key, file_path=None)
   enc_text = enc.encrypt()
   print(enc_text)

   dec = Decrypt(enc_text, aes_key)
   print(dec.decrypt())
```
   Gives below output:
```
   Encrypted output:
   @encrypted_a74d5a8ddc0c1c79ee5ecf0a2a28a33ba54ac7dde4f47fef9e9ea4c010bf22e5492de6f54334b4b4d8152ce3d6f902a4e554fffded6a53fad7b6360049e95e35ab4b3e2d35625606693825a77ff0f4fb10c5f7

   Decrypted output:
   the password fake_password secret fake_secret_1 fake_secret_2 three
```









