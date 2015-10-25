import random as rnd

#number of try to generate modulo
nrepeat =  50000

#number_bits_modulo should be at least number_bits_cipher_block
number_bits_modulo = 155

#number_bits_cipher_block should be: 8*1, 8*2, 8*3, 8*4, 8*5, ..., 8*n
#number_bits_cipher_block should be less than number_bits_modulo
number_bits_cipher_block = 32

cipher_block_in_bytes = number_bits_cipher_block / 8

pubkeyfname = 'pubkey.txt'
prikeyfname = 'prikey.txt'
ptextfname = 'ptext.txt'
ctextfname = 'ctext.txt'
dtextfname = 'dtext.txt'

def readPlaintext():
    with open(ptextfname, 'rb') as f:
        d = 1
        while (d != ''):
            i = 0
            result = 0
            while (i < cipher_block_in_bytes):
                d = f.read(1)
                if (d == ''):
                    break
                result = result << 8 | ord(d)
                i = i + 1
            if (result != 0xa and result > 0):
                yield result << (8 * (cipher_block_in_bytes-i))

def readCiphertext():
    with open(ctextfname, 'r') as f:
        for line in iter(f):
            yield line

def getbyteAt(k, n, l = 1):
    return (k >> (n * 8 * l)) & (2**(8*l) - 1)

def convertToBuffer(msg):
    b = bytearray([])
    for i in range(cipher_block_in_bytes):
        c = getbyteAt(msg, cipher_block_in_bytes - i - 1)
        if (c > 0):
            b.append(c)
    return b
            
#Miller Rabin
def millerRabinPrimeTest(n):
    testInts = [2, 3, 5, 7, 11, 13, 17, 23, 31, 61, 73, 1662803]
    k = 0
    n1 = n - 1
    q = n1
    while (q & 1 == 0):
        k = k + 1
        q = q / 2   
    rangek = xrange(k + 1)
    for a in rnd.sample(testInts, 4):
        if (a > n or pow(a, q, n) == 1):
            continue
        for j in rangek:
            if (j == k):
                return False
            if (pow(a, pow(2, j) * q, n) == n1):
                break
    return True

def computeModulo():
    print '   Generating a {0}-bit prime with {1} trial times. Please wait'.format(number_bits_modulo,nrepeat)
    k = number_bits_modulo - 2
    minp = pow(2, k) + 1
    maxp = pow(2, k + 1) - 1
    index = 0
    while (index < nrepeat):
        q = rnd.randrange(minp, maxp, 2)
        if (millerRabinPrimeTest(q) == False):
            index = index + 1
            continue
        p = 2 * q + 1
        if (millerRabinPrimeTest(p) == False):
            index = index + 1
            continue
        print '   Generating a {0}-bit prime after {1} trial times '.format(number_bits_modulo, index)
        return (2, p)
    print "   Can't generate a {0}-bit prime. Please try again or reduce number of bits".format(number_bits_modulo)
    return None

def computeKeyFiles(priKey):  
    computeResults = computeModulo()
    if (computeResults == None):
        return False
    
    e1 = computeResults[0]
    p = computeResults[1]
    e2 = pow(e1, priKey, p)

    writeKeyFiles(p, e1, e2, priKey)
    return True

def setupKeyFiles(modulo, generator, priKey):
    e2 = pow(generator, priKey, modulo)
    writeKeyFiles(modulo, generator, e2, priKey)

def writeKeyFiles(p, e1, e2, d):
    with open(pubkeyfname, 'w') as f:
        f.write('{0} {1} {2}'.format(p, e1, e2))

    with open(prikeyfname, 'w') as f:
        f.write('{0} {1} {2}'.format(p, e1, d))    

def computeCiphers(msg, p, e1, e2, r):
    c1 = pow(e1, r, p)
    c2 = ((msg % p) * pow(e2, r, p)) % p
    return (c1,c2)

def computeDecipher(ciphers, p, d):
    dc1 = pow(ciphers[0], p - 1 - d, p)
    dc2 = ciphers[1] % p
    return (dc1 * dc2) % p

def encrypt():
    with open(pubkeyfname, 'r') as f:
        splits = f.read().split()
        p = int(splits[0], 10)
        e1 = int(splits[1], 10)
        e2 = int(splits[2], 10)

    with open(ctextfname, 'w') as f:
        for msg in readPlaintext():
            print '_______'
            print 'PLAINTEXT: ', '{0:x}'.format(msg)
            ciphers = computeCiphers(msg, p, e1, e2, rnd.randrange(p))
            f.write('{1} {0}\n'.format(ciphers[0], ciphers[1]))

def decrypt():
    with open(prikeyfname, 'rb') as f:
        splits = f.read().split()
        p = int(splits[0], 10)
        e1 = int(splits[1], 10)
        d = int(splits[2], 10)

    with open(dtextfname, 'w') as f:
        for line in readCiphertext():
            splits = [int(n,10) for n in line.split(' ')]
            msg = computeDecipher((splits[1],splits[0]), p, d)
            f.write(convertToBuffer(msg))
    
