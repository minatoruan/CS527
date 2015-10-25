import publickeyCrypto as crypto

prikey = 2007
p = 1750363172452868841489802775448401519251016944987788641802814992129198737381711667368645927
e1 = 2

#ASCII format
def create_plaintext_file():
    plaintext = 'Hello!!! This is an implementation of public-key cryptography with block size {0}.\n'.format(crypto.number_bits_cipher_block)
    plaintext += 'The auto-computed modulo is {0}-bits.\n'.format(crypto.number_bits_modulo)
    plaintext += 'This message has number of lines more than two.'
    with open(crypto.ptextfname, 'w') as f:
        f.write(plaintext)

def printKeyFiles():
    print '   public key file:'
    with open(crypto.pubkeyfname, 'r') as f:
        splits = f.read().split()
        p_pubfname = int(splits[0], 10)
        e1_pubfname = int(splits[1], 10)
        e2_pubfname = int(splits[2], 10)
        print '      p:', p_pubfname
        print '      e1(g):', e1_pubfname
        print '      e2:', e2_pubfname

    print '   private key file:'
    with open(crypto.prikeyfname, 'r') as f:
        splits = f.read().split()
        p_prifname = int(splits[0], 10)
        e1_prifname = int(splits[1], 10)
        d_prifname = int(splits[2], 10)
        print '      p:', p_prifname
        print '      e1(g):', e1_prifname
        print '      d:', d_prifname        

def auto_compute_p_and_generator_encryption_decryption():
    print '_______________________________________________'
    print 'Public-key cryptography computes key files'
    crypto.computeKeyFiles(prikey)
    printKeyFiles()
  
    print '_______________________________________________'
    print 'Write a plaintext'
    create_plaintext_file()
    with open(crypto.ptextfname, 'r') as f:
        print f.read()

    print '_______________________________________________'
    print 'Public-key cryptography ENCRYPTION'
    crypto.encrypt()

    print '_______________________________________________'
    print 'Public-key cryptography DECRYPTION'
    crypto.decrypt()
    with open(crypto.dtextfname, 'r') as f:
        print f.read()

    print '\nDone!!!'

def setup_key_files_encryption_decryption():
    print '_______________________________________________'
    print 'Public-key cryptography computes key files'
    crypto.setupKeyFiles(p, e1, prikey)
    printKeyFiles()
  
    print '_______________________________________________'
    print 'Write a plaintext'
    create_plaintext_file()
    with open(crypto.ptextfname, 'r') as f:
        print f.read()    

    print '_______________________________________________'
    print 'Public-key cryptography ENCRYPTION'
    crypto.encrypt()

    print '_______________________________________________'
    print 'Public-key cryptography DECRYPTION'
    crypto.decrypt()
    with open(crypto.dtextfname, 'r') as f:
        print f.read()    

    print '\nDone!!!'

if __name__ == '__main__':
    auto_compute_p_and_generator_encryption_decryption()
    #setup_key_files_encryption_decryption()
