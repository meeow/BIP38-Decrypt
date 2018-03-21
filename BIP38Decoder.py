''''
- BIP 0038 SPEC -
https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki#Decryption

Decryption
Collect encrypted private key and passphrase from user.
Derive passfactor using scrypt with ownersalt and the user's passphrase and use it to recompute passpoint
Derive decryption key for seedb using scrypt with passpoint, addresshash, and ownerentropy
Decrypt encryptedpart2 using AES256Decrypt to yield the last 8 bytes of seedb and the last 8 bytes of encryptedpart1.
Decrypt encryptedpart1 to yield the remainder of seedb.
Use seedb to compute factorb.
Multiply passfactor by factorb mod N to yield the private key associated with generatedaddress.
Convert that private key into a Bitcoin address, honoring the compression preference specified in the encrypted key.
Hash the Bitcoin address, and verify that addresshash from the encrypted private key record matches the hash. If not, report that the passphrase entry was incorrect.
'''
import scrypt
from Crypto.Cipher import AES

n, r, p, l = 16384, 8, 8, 64

def get_user_params():
    encrypted_private_key = input("Enter your BIP-38 encrypted private key:")
    passphrase = input("Enter your passphrase for your encrypted private key:")
    return encrypted_private_key, passphrase

# Translated from js: https://github.com/cryptocoinjs/bs58
def bs58_decode(string):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    alphabet_dict = { alphabet[i]:i for i in range(len(alphabet)) }

    bytes = [0]

    for i in range(len(string)):
        c = string[i]
        #assert(c in alphabet_dict)
        for j in range(len(bytes)):
            bytes[j] *= len(alphabet)
        bytes[0] += alphabet_dict[c]

        carry = 0
        for j in range(len(bytes)):
            bytes[j] += carry
            carry = bytes[j] >> 8
            bytes[j] &= 0xff

        while carry:
            bytes.append(carry & 0xff)
            carry >>= 8

    i = 0
    while (string[i] == '1' and i < len(string) - 1):
        i += 1
        bytes.append(0)

    return bytes[::-1][:-4]

# WIP
# Translating from: https://github.com/bitcoinjs/bip38/blob/master/index.js
def decrypt(encrypted_private_key, passphrase):
    bs58_decoded_pk = bs58_decode(encrypted_private_key) 
    salt = bs58_decoded_pk[3:7]
    #scrypt_hash = scrypt.hash(passphrase, salt, N=n, r=r, p=p, buflen=l)
    scrypt_hash = scrypt.hash (passphrase, salt, N=16384, r=8, p=8, buflen=64)

    half1, half2 = scrypt_hash[:32], scrypt_hash[32:]
    pk_slice = bs58_decoded_pk[7:7+32]
    cipher = AES.new(key=half2, mode=AES.MODE_ECB)
    decipher = cipher.decrypt(pk_slice)

    decipher.setAutoPadding(false)
    print (decipher)

# Throwaway keys
def main():
    encrypted_private_key, passphrase = '5JyfkWSkZaLXCKZqsj2n4LgZFGcPZgt25KqYMEVgo2AKAXCtfL6', 'pass'#get_user_params()
    decrypt(encrypted_private_key, passphrase)
    print ([format(i, '02x') for i in bs58_decode('5Kd3NBUAdUnhyzenEwVLy9pBKxSwXvE9FMPyR4UKZvpe6E3AgLr')])
main()

