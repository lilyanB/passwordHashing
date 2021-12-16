# passwordHashing

Lilyan BASTIEN 2021

## Usage of the scripts

First you need to install all requirements.

```bash
pip install tink
pip install bcrypt
```

To initiate connection and test writing in your google collabory:

```python
from google.colab import drive
drive.mount('/content/gdrive', force_remount=True)
with open('/content/gdrive/MyDrive/test.txt', 'w') as f:
  f.write('values')
```

Use theyr files on google collabory. You can change their to run on your computer.

## How to calculate the strength of a password?

### **Question 1**: What is minimum length of a password created from case-insensitive alphanumeric and having 64-bit of entropy?

We have H = 64bits. As we only use 36 characters, the password has to be minimum 13 characters (12.37928983150533).

## How to securely store user passwords?

## Naive solution

The naive approach would be to store the password as hash like sha 1, 2, ...

```py
hashpass = sha3(password)
store(hashpass)
```

## Increasing the entropy

You can add salt before the hash. Then, an hacker must only brute force password 1 by 1.

```py
salt = os.urandom(32)
hashpass = scrypt(salt + password)
store(salt, hashpass)
```

## Which hashing algorithm to use

Script, argon 2, bcrypt, WPA, DES

## Data breaches and how to deal with it

Use asymmetric encryption with a secret key. As we have only one secret key for our whole app, it is easier to secure.

```py
salt = os.urandom(32)
hashpass = scrypt(salt + password)
# Deterministic encryption
encrypted_hashpass = encryption_machine(hashpass)
store(salt, encrypted_hashpass)
```