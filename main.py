import tink
import bcrypt
from tink import daead
from tink import cleartext_keyset_handle

database = 'it is my data'
secret_key = 'xxx' # use Tink to generate your secret key here
#salt1 = bcrypt.gensalt()
salt1 = b'$2b$12$c8rMM5Rh2FF47dEiJmqW7O'
print("my salt : " , salt1)

#encryption_machine
daead.register()
keyset_handle = tink.new_keyset_handle(daead.deterministic_aead_key_templates.AES256_SIV)
daead_primitive = keyset_handle.primitive(daead.DeterministicAead)

def hash_password(pwd: str, salt):
  # implement your schema
  # use bcrypt to hash the password
  hashed_password = bcrypt.hashpw(pwd.encode(), salt)
  return hashed_password, salt
  #return hash

def encryption_machine(msg):
  # encrypt using AES-SIV
  associated_data = b"associated data"
  ciphertext = daead_primitive.encrypt_deterministically(msg, associated_data)
  return ciphertext

def save_to_database(user, pwd):
  # use a file as a database
  # format: user, hashed_password
  # for example: file.write(user, hash_password(pwd))

  hashed_password, salt = hash_password(pwd,salt1)
  encrypted_password = encryption_machine(hashed_password)
  print("my hashed_password is " , hashed_password)
  print("my salt is " , salt)
  print(" my encrypted_password is " , encrypted_password)
  with open('/content/gdrive/MyDrive/projet crypto/data.txt', 'a') as f:
    f.write(f'{user},{encrypted_password.hex()},{salt.hex()}\n')
  return encrypted_password.hex()

def check_password(user, pwd):
    # read from database
  with open('/content/gdrive/MyDrive/projet crypto/data.txt', 'r') as f:
    for line in f.readlines():
      user_in_database, encrypted_password, salt = line.split(',')
      print(user_in_database)
      print(encrypted_password)
      print(salt)
      if user == user_in_database:
        hashed_password, u= hash_password(pwd, salt1)
        # and check for authentication
        encrypted_user_password = encryption_machine(hashed_password)
        if encrypted_user_password == bytes.fromhex(encrypted_password):
          return True
  return False


print(hash_password(database, salt1)) #c'est good
a, b=hash_password(database, salt1)
print("a is " , a)
print("b is " , b)
print("my encrypted_password who save  is " , encryption_machine(a)) #c'est good

f = save_to_database('lilyan',database)
print("my data save is ",f)
print(" ")


print(check_password('lilyan',database))