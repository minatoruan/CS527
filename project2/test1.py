import publickeyCrypto as crypto
from test import *
import os

def checkFileExist(fn):
    if not os.path.isfile(fn):
        print 'No file: ', fn
        return False
    return True

def chooseAction():
    print '_______________________________________________________________________________'
    print 'Welcome to public-private key encryption python script:'
    print 'The script was build with {0}-bit module and {1}-bit cipher block.\n'.format(crypto.number_bits_modulo, crypto.number_bits_cipher_block) 
    print 'Please choose either following actions:\n'
    print '0. Run a built-in simple test case\n'
    print '1. Setup key (input: p,g,prikey; output: pubkey and prikey in key files)\n'
    print '2. Auto compute key (input: prikey; output: pubkey and prikey in key files)\n'
    print '3. Setup a demo plaintext\n'
    print '4. Encrypt the plaintext (dependent on either step 1 or 2, and step 3)\n'
    print '5. Decrypt the ciphertext (The ctext.txt must be existed)\n'
    print '6. Quit\n'
    return input('Enter your choice (0-6): ')
    
def callAction(choice):
    if (choice == 0):
        auto_compute_p_and_generator_encryption_decryption()
        return 1

    if (choice == 1):
        print '_______________________________________________'
        print 'Public-key cryptography computes key files'
        m = input('Enter your computed modulo: ')
        g = input('Enter your computed generator: ')
        pri = input('Enter your private key: ')
        crypto.setupKeyFiles(m, g, pri)
        printKeyFiles()
        return 1

    if (choice == 2):
        print '_______________________________________________'
        print 'Public-key cryptography computes key files'
        pri = input('Enter your private key: ')
        if (crypto.computeKeyFiles(pri)): printKeyFiles()
        return 1

    if (choice == 3):
        print '_______________________________________________'
        print 'Write a plaintext'
        create_plaintext_file()
        with open(crypto.ptextfname, 'r') as f:
            print f.read()
        return 1

    if (choice == 4):
        print '_______________________________________________'
        print 'Public-key cryptography ENCRYPTION'
        if (not checkFileExist(crypto.pubkeyfname) or
            not checkFileExist(crypto.prikeyfname) or
            not checkFileExist(crypto.ptextfname)):
            print 'No required files for encryption'
            return 1
        crypto.encrypt()
        print 'Done'
        return 1

    if (choice == 5):
        print '_______________________________________________'
        print 'Public-key cryptography DECRYPTION'
        if (not checkFileExist(crypto.pubkeyfname) or
            not checkFileExist(crypto.prikeyfname) or
            not checkFileExist(crypto.ptextfname)):
            print 'No required files for decryption'
            return 1        
        crypto.decrypt()
        with open(crypto.dtextfname, 'r') as f:
            print f.read()
        print 'Done'
        return 1

    return 0

if __name__ == '__main__':
    while(True):
        if (callAction(chooseAction()) == 0):
            break
