import twofishdecryptoalgo as d
import twofishcryptoalgo as e

plaintext_filename = 'plaintext.txt'
ciphertext_filename = 'ciphertext.txt'
deciphertext_filename = 'deciphertext.txt'
key_filename = 'key.txt'

#ASCII format
def create_plaintext_file(filename):
    plaintext = 'Hello!!! This is an implementation of WSU cryptography that uses 80 bits key.'
    plaintext += '\n'
    plaintext += 'This message has two lines.'
    fp = open(filename, 'w')
    fp.write(plaintext)
    fp.close()

#HEX format
def create_key_file(filename):
    key = 'abcdef0123456789abcd'
    key = '0' + key
    fp = open(filename, 'w')
    fp.write('{0:20x}'.format(int(key, 16)).replace(' ', '0'))
    fp.close()

#plaintextfile : filename of plaintext file
#keyfile : filename of key file
#cipherfile: output of encryption result (plaintext -> ciphertext)
#decipherfile: output of decipher result (ciphertext -> deciphertext)
#plaintext must be equal to deciphertext with the same key input
def test_intergration_encryption_decryption(plaintextfile, keyfile, cipherfile, decipherfile):
    print '_______________________________________________'
    print 'WSU ENCRYPTION'
    #e.encrypt(plaintextfile, keyfile, cipherfile)

    print '_______________________________________________'
    print 'WSU DECRYPTION'
    d.decrypt(cipherfile, keyfile, decipherfile)

    print '_______________________________________________'
    print 'KEY FILE (HEX) 80 bits'
    fp = open(keyfile, 'r')
    print fp.readline()
    fp.close()  

    print '_______________________________________________'
    print 'PLAINTEXT FILE'
    fp = open(plaintextfile, 'r')
    print fp.readline()
    fp.close()

    print '_______________________________________________'
    print 'DECIPHERTEXT FILE'
    fp = open(decipherfile, 'r')
    print fp.readline()
    fp.close()

    print '_______________________________________________'
    print 'CIPHERTEXT FILE (HEX)'
    fp = open(cipherfile, 'r')
    print fp.readline()
    fp.close()    

if __name__ == '__main__':
    create_plaintext_file(plaintext_filename)
    create_key_file(key_filename)
    test_intergration_encryption_decryption(plaintext_filename,
                                            key_filename,
                                            ciphertext_filename,
                                            deciphertext_filename)
