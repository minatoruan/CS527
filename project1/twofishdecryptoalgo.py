import common as c

# k: string of key - 10 bytes, it represents in HEX format, e.g: abcdef0123456789abcd
def generateSubkeys(k):
    arr = [0 for x in range(12 * c.numround)]
    i = 0
    for rnd in range(c.numround - 1, -1, -1):
        for x in range(11, -1, -1):
            arr[i*12 + x] = c.getbyteAt(k, ((4 * rnd) + (x % 4)) % c.keylen)
            k = c.ror(k, c.keylen*8)
        i += 1
    return arr

#w has 2 byte
def gfunc(w, keyyielder):
    g1 = c.getbyteAt(w, 1)
    g2 = c.getbyteAt(w, 0)
    g3 = c.fvalue(g2 ^ keyyielder()) ^ g1
    g4 = c.fvalue(g3 ^ keyyielder()) ^ g2
    g5 = c.fvalue(g4 ^ keyyielder()) ^ g3
    g6 = c.fvalue(g5 ^ keyyielder()) ^ g4
    return c.concat(g5, g6) 

#w0, w1 has 2 byte
def ffunc(w0, w1, keyyielder):
    t0 = gfunc(w0, keyyielder)
    t1 = gfunc(w1, keyyielder)
    f0 = (t0 + 2 * t1 + c.concat(keyyielder(), keyyielder())) % c.twosquaresixteen
    f1 = (2 * t0 + t1 + c.concat(keyyielder(), keyyielder())) % c.twosquaresixteen
    return [f0, f1]

# wArr[0-3]
def roundfunc(wArr, keyyielder):
    newArr = [0, 0, 0, 0]
    fvalues = ffunc(wArr[0], wArr[1], keyyielder)
    newArr[0] = c.rol(wArr[2], 16) ^ fvalues[0]
    newArr[1] = c.ror(wArr[3] ^ fvalues[1], 16) 
    newArr[2] = wArr[0]
    newArr[3] = wArr[1]
    return newArr

#read hex
def readCiphertext(fn):
    reader = c.hexreader(fn)
    d = 1
    while not (d is None):
        i = 0
        result = 0
        while (i < c.plaintextlen * 2):
            d = reader()
            if (d is None):
                break
            result = result << 4 | d
            i += 1
        if (result != 0xa and result > 0):
            yield result << (4 * (c.plaintextlen*2-i))

# fn: filename
def readKey(fn):
    reader = c.hexreader(fn)
    k = 0
    for i in range(c.keylen * 2):  
        k = k << 4 | reader()
    return k

#encrypt __inner
def __encrypt__ (p, k, keyyielder):
    w = c.whitening(p, k)
    arr = [c.getbyteAt(w, 3, 2),
            c.getbyteAt(w, 2, 2),
            c.getbyteAt(w, 1, 2),
            c.getbyteAt(w, 0, 2)]
    for rnd in range(c.numround):
        arr = roundfunc(arr, keyyielder)
    y = c.concat(c.concat(arr[2], arr[3], 2),
                 c.concat(arr[0], arr[1], 2),
                 4)
    ci = c.whitening(y, k)
    return [c.getbyteAt(ci, 3, 2),
                c.getbyteAt(ci, 2, 2),
                c.getbyteAt(ci, 1, 2),
                c.getbyteAt(ci, 0, 2)]

# pfn: name of plaintext file, e.g: plaintext.txt
# kfn: name of key file, it represents in HEX format, e.g: key.txt
# cfn: name of cipher, output file, e.g: cipher.txt
def decrypt(cfn, kfn, pfn):
    k = readKey(kfn)
    keyyielder = c.yielder(generateSubkeys(k))
    output = c.charwriter(pfn)

    for ci in readCiphertext(cfn):
        print '_______'
        print 'CIPHERTEXT: ', '{0:x}'.format(ci)
        p = __encrypt__(ci, k, keyyielder)
        for j in range(4):
            if (p[j] > 0):
                output(p[j])
        print 'PLAINTEXT'
        print '{0:x}'.format(p[0]), '{0:x}'.format(p[1]), '{0:x}'.format(p[2]),'{0:x}'.format(p[3])

if __name__ == '__main__':
    decrypt(c.cfile, c.kfile, c.pfile)
