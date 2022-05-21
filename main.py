from Crypto.Cipher import AES
from secrets import token_bytes

k = token_bytes(16) # key `k` our key that is 16 bytes

# AES encryption 
def encrypt(msg): # function
    cipher = AES.new(k, AES.MODE_EAX) # mode and new aes encryption type
    nonce = cipher.nonce # nonce cipher
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii')) # digests and encrypts in ascii form
    return nonce, ciphertext, tag # returns the variables

# AES decryption
def decrypt(nonce, ciphertext, tag): # function
    cipher = AES.new(k, AES.MODE_EAX, nonce=nonce) # mode and aes decryption
    plain = cipher.decrypt(ciphertext) # decrypts the encrypted text provided
    try:
        cipher.verify(tag) # tries to very the tag
        return plain.decode('ascii') # returns it as a plain text decode
    except: # if it doesnt work it comes back as false / negative
        return False

# spits out gay shit
nonce, ciphertext, tag = encrypt(input('Enter a message: ')) # grabs all variable jumbles it or wtv makes it a input and spits out the decrypted and encrypted msg
plain = decrypt(nonce, ciphertext, tag) # decrypted part
print(f'Cipher text: {ciphertext}') # encrypted AES msg
if not plain: # if it isnt plain text
    print('Message is corrupted 404:') # gives error of corruption
else: #if it is plain text
    print(f'Plain text: {plain}') # spits out the text

''' src from docs first time doing this https://pycryptodome.readthedocs.io/en/latest/index.html k bye this isnt skidded just changed most things '''