import time
import unittest
import publickeyCrypto as crypto

class Timer:    
    def __enter__(self):
        self.start = time.clock()
        return self

    def __exit__(self, *args):
        self.end = time.clock()
        self.interval = self.end - self.start

class publicketCryptoTest(unittest.TestCase):

    def setUp(self):
        self.p = 11534899272561676244925313717014331740490094532609834959814346921905689869862264593212975473787189514436889176526473093615929993728061165964347353440008577
        self.e1 = 2
        self.e2 = 3588482756928295630140943685051615894367297718030112874166464509736235480183708076087696748586815287503034124154961159603686751686822260389353093996813962
        self.d = 1007
        self.text = 'Hello! this is public-key cryptosystem.'
        self.text1 = 'Implemented by Duc Nguyen'
        self.shorttext = 'a'
        pass

    def test_mod(self):
        self.assertEqual(1, pow(7,0,11))
        self.assertEqual(7, pow(7,1,11))
        self.assertEqual(5, pow(7, 2, 11))
        self.assertEqual(2, pow(7, 3, 11))
        self.assertEqual(3, pow(7, 4, 11))
        self.assertEqual(10, pow(7, 5, 11))

    def test_millerRabinPrimeTesttest_mod(self):
        self.assertEqual(False, crypto.millerRabinPrimeTest(221))
        self.assertEqual(False, crypto.millerRabinPrimeTest(220))
        self.assertEqual(True, crypto.millerRabinPrimeTest(137))
        self.assertEqual(False, crypto.millerRabinPrimeTest(2047))

        with Timer() as t:
            r = crypto.millerRabinPrimeTest(7337488745629403488410174275830423641502142554560856136484326749638755396267050319392266204256751706077766067020335998122952792559058552724477442839630133)
        self.assertEqual(True, r)

    def test_generate_modulo_high_bit_always_1(self):
        with Timer() as t:
            p = crypto.computeModulo()
        print 'Generating a prime took', t.interval
        print 'g,p = ', p
        print 'generated prime:', p[1]
        self.assertEqual(True, p[1] > pow(2,32))
        self.assertEqual(True, crypto.millerRabinPrimeTest(p[1]))
        self.assertEqual(crypto.number_bits_modulo, len(bin(p[1])) - 2)

    def test_computeKeyFiles(self):
        priKey = 2007
        crypto.computeKeyFiles(priKey)

        with open(crypto.pubkeyfname, 'r') as f:
            splits = f.read().split()
            p_pubfname = int(splits[0], 10)
            e1_pubfname = int(splits[1], 10)
            e2_pubfname = int(splits[2], 10)

        with open(crypto.prikeyfname, 'r') as f:
            splits = f.read().split()
            p_prifname = int(splits[0], 10)
            e1_prifname = int(splits[1], 10)
            d_prifname = int(splits[2], 10)

        self.assertEqual(p_pubfname, p_prifname)
        self.assertEqual(True, crypto.millerRabinPrimeTest(p_pubfname))

        self.assertEqual(2, e1_pubfname)
        self.assertEqual(2, e1_prifname)
        
        self.assertEqual(e2_pubfname, pow(e1_pubfname, d_prifname, p_pubfname))
        self.assertEqual(priKey, d_prifname)
        
    def test_setupKeyFiles(self):
        crypto.setupKeyFiles(self.p, self.e1, self.d)

        with open(crypto.pubkeyfname, 'r') as f:
            splits = f.read().split()
            p_pubfname = int(splits[0], 10)
            e1_pubfname = int(splits[1], 10)
            e2_pubfname = int(splits[2], 10)

        with open(crypto.prikeyfname, 'r') as f:
            splits = f.read().split()
            p_prifname = int(splits[0], 10)
            e1_prifname = int(splits[1], 10)
            d_prifname = int(splits[2], 10)

        self.assertEqual(p_pubfname, p_prifname)
        self.assertEqual(p_pubfname, self.p)
        self.assertEqual(True, crypto.millerRabinPrimeTest(self.p))

        self.assertEqual(2, e1_pubfname)
        self.assertEqual(2, e1_prifname)
        
        self.assertEqual(e2_pubfname, pow(e1_pubfname, d_prifname, p_pubfname))
        self.assertEqual(self.e2, pow(2,1007,self.p))

        self.assertEqual(self.d, d_prifname)
        print 'e2: ', pow(2,1007,self.p)
        
    def test_computeCiphers(self):
        msg = 3200
        r = 545131

        ciphers = crypto.computeCiphers(msg, self.p, self.e1, self.e2, r)
        deciphertext = crypto.computeDecipher(ciphers, self.p, self.d)

        self.assertEqual(msg, deciphertext)

    def test_encrytion_one_line(self):
        crypto.setupKeyFiles(self.p, self.e1, self.d)
        
        with open(crypto.ptextfname, 'w') as f:
            f.write(self.text)

        crypto.encrypt()
        crypto.decrypt()

        with open(crypto.dtextfname, 'r') as f:
            lines = f.readlines()
            self.assertEqual(1, len(lines))
            self.assertEqual(self.text, lines[0])

    def test_encrytion_two_lines(self):
        crypto.setupKeyFiles(self.p, self.e1, self.d)
        
        with open(crypto.ptextfname, 'w') as f:
            f.write(self.text)
            f.write('\n')
            f.write(self.text1)

        crypto.encrypt()
        crypto.decrypt()

        with open(crypto.dtextfname, 'r') as f:
            lines = f.readlines()
            self.assertEqual(2, len(lines))
            self.assertEqual(self.text, lines[0].replace('\n',''))
            self.assertEqual(self.text1, lines[1])

    def test_encrytion_short_msg(self):
        crypto.setupKeyFiles(self.p, self.e1, self.d)
        
        with open(crypto.ptextfname, 'w') as f:
            f.write(self.shorttext)

        crypto.encrypt()
        crypto.decrypt()

        with open(crypto.dtextfname, 'r') as f:
            lines = f.readlines()
            self.assertEqual(1, len(lines))
            self.assertEqual(self.shorttext, lines[0])
        
if __name__ == '__main__':
    unittest.main()
