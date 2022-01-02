import tink
import bcrypt
from tink import daead
from tink import cleartext_keyset_handle

def read_keyset():
  try:
    with open("/content/gdrive/MyDrive/projet crypto/keyset.json", 'rt') as f:
      return cleartext_keyset_handle.read(tink.JsonKeysetReader(f.read()))
  except:
    daead.register()
    keyset_handle = tink.new_keyset_handle(daead.deterministic_aead_key_templates.AES256_SIV)
    with open("/content/gdrive/MyDrive/projet crypto/keyset.json", 'wt') as f:
      return cleartext_keyset_handle.write(tink.JsonKeysetWriter(f), keyset_handle)

#encryption_machine
daead.register()
keyset_handle = read_keyset()
daead_primitive = keyset_handle.primitive(daead.DeterministicAead)

def generSalt():
  secret_key=bcrypt.gensalt()
  return secret_key


def hash_password(pwd, salt):
  # implement your schema
  # use bcrypt to hash the password
  hashed_password = bcrypt.hashpw(pwd.encode(), salt)
  return hashed_password, salt
  #return hash

def encryption_machine(msg):
  associated_data = b"associated data"
  ciphertext = daead_primitive.encrypt_deterministically(msg, associated_data)
  return ciphertext

def save_to_database(user, pwd):
  # use a file as a database
  # format: user, hashed_password
  # for example: file.write(user, hash_password(pwd))

  hashed_password, salt = hash_password(pwd,generSalt())
  encrypted_password = encryption_machine(hashed_password)
  print("my hashed_password is " , hashed_password)
  print("my salt is " , salt)
  print("my encrypted_password is " , encrypted_password)
  with open('/content/gdrive/MyDrive/projet crypto/data.txt', 'a') as f:
    f.write(f'{user},{encrypted_password.hex()},{salt.hex()}\n')
  return encrypted_password.hex()

def check_password(user, pwd):
    # read from database
  with open('/content/gdrive/MyDrive/projet crypto/data.txt', 'r') as f:
    for line in f.readlines():
      user_in_database, encrypted_password, salt= line.split(',')
      print(user_in_database)
      print(encrypted_password)
      print(salt)
      if user == user_in_database:
        hashed_password, u= hash_password(pwd, bytes.fromhex(salt))
        # and check for authentication
        encrypted_user_password = encryption_machine(hashed_password)
        if encrypted_user_password == bytes.fromhex(encrypted_password):
          return True
  return False

database=input("what do you want to save? or see if it's almost save?")
print("I will save this data : ", database)

answers=input("You want save database(s)? You want verify database(v)? or both(b)? ")
if answers=="s":
  hashpass, saltgen=hash_password(database, generSalt())
  user1=input("give your user and I save with : ")
  print("it's save with : ",user1)
  save = save_to_database(user1,database)
  print("my data save is ",save)
  print(" ")
if answers=="v":
  user2=input("give your user to test : ")
  print(check_password(user2,database))
if answers=="b":
  hashpass, saltgen=hash_password(database, generSalt())
  print("my hashed_password for this pass is : " , hashpass)
  print("my salt for this pass is : " , saltgen)
  print("my encrypted_password who save  is " , encryption_machine(hashpass))
  user=input("give your user and I save with : ")
  print("it's save with : ",user1)
  save = save_to_database(user,database)
  print("my data save is ",save)
  print(" ")
  print(check_password(user,database))
else:
  print("good bye")