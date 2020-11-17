#https://gist.github.com/Xpktro/6549868

import binascii
class BinString(str):
    """
    Native Python str extension to validate binary-numbers-only strings and
    support for some bitwise operations needed by DES.
    """

    def __init__(self, *args, **kwargs):
        """
        Instance constructon, validates that the input string is made of
        zeros and ones only.
        """
        #super(BinString, self).__init__(*args, **kwargs)
        #for char in self:
        #    if not char in ('0', '1'):
        #        raise ValueError('Invalid input string for BinString')

    def __xor__(self, other):
        """
        Bitwise XOR ( ^ ) operator overloading for convenience.
        """
        assert type(other) in (str, BinString), \
            'Undefined XOR (^) operation for type %s' % type(other)

        if type(other) is str:
            for char in other:
                if not char in ('0', '1'):
                    raise ValueError(
                        'Undefined XOR (^) operation for string %s' % other
                    )

        result = bin(int(self, 2) ^ int(other, 2))[2:]

        while len(result) < len(self):
            result = '0' + result

        while len(result) < len(other):
            result = '0' + result

        return BinString(result)

    def __lshift__(self, n):
        """
        Bitwise left shift (<<) operator overloading for convenience.
        """
        result = self[:]
        for i in range(n):
            result = result[1:] + result[0]
        return BinString(result)

    def __getslice__(self, i, j):
        """
        Standard string slicing wrapping.
        """
        return BinString(super(BinString, self).__getslice__(i, j))


class StringConverter(object):
    """
    'Abstract' string conversion class. Defines an interface to be used by the
    DES algorythm class so the conversion engine can be seamlessly switched.
    """
    @staticmethod
    def to_hex(input_):
        """
        Should translate a plain unicode string input to a python standard
        string in pure hexadecimal format, without any special quotation. Also,
        the resulting string must contain a number of digits divisible by 64.
        """
        raise NotImplementedError

    @staticmethod
    def from_hex(input_):
        """
        Should translate a standard python string input consisting of
        hexadecimal digits to a plain unicode string.
        """
        raise NotImplementedError

    @classmethod
    def to_bin(cls, s, hexstring=False):
        """
        Converts a string (possibly containing hexadecimal digits) to its
        binary-string form (each digit with 4-zeros fill).
        """
        string = cls.to_hex(s) if not hexstring else s
        bits = ''
        for char in string:
            #print(char,"--",bits)
            bits += bin(int(char, 16))[2:].zfill(4)
        while len(bits) % 64 != 0:
            bits += '0'
        return BinString(bits)

    @classmethod
    def from_bin(cls, s, hexstring=False):
        """
        Converts a binary-digit-only string to its plain or
        hexadecimal-digit-only form.
        """
        result = ''
        for i in range(0, len(s), 4):
            result += hex(int(s[i:i+4], 2))[2:]
        return result if hexstring else cls.from_hex(result)


class BinasciiConverter(StringConverter):

    """
    String conversion class using the standard library binascii module.
    """

    @staticmethod
    def to_hex(input_):
        return binascii.hexlify(str(input_).encode('utf-8'))
        #return binascii.hexlify(unicode(input_).encode('utf-8'))

    @staticmethod
    def from_hex(input_):
        return binascii.unhexlify(input_).decode('utf-8')


class DES(object):
    """
    The DES cipher implementation class.
    This implementation is for academic pruposes only, it was made to show the
    procedures and principles behind the DES algorithm in a
    not-so-programmatically-hard way and it's _highly_ inefficient when used
    in real life situations. You must never use this implementation outside
    it's original prupose.
    """

    # Permutation tables
    PC_1 = [
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    ]

    PC_2 = [
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ]

    PI = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]

    E = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]

    # S boxes
    S = [

    	#S2
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
        ],


        #S1
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],



        #S3
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
        ],

        #S4
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
        ],

        #S5
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
        ],

        #S6
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
        ],

        #S7
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
        ],

        #S8
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
        ]
    ]

    P = [
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25,
    ]

    PI_1 = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25,
    ]

    def _validate_length(self, string, length):
        """Simple string length validation."""
        assert len(string) == length, \
            'String %s length\'s not %s' % (string, length,)

    def _group_by(self, string, by):
        """
        Outputs a list of strings, each part being a slice of 'by' characters
        from 'string'.
        """
        return [string[i:i+by] for i in range(0, len(string), by)]

    def _set_key(self, key, hexkey=False):
        """
        Performs the input key conversion to binary and sets it as an
        instance variable.
        """
        self.key = self.converter.to_bin(key, hexkey)

    def _set_message(self, string, hexstring=False):
        """
        Performs the input message conversion to binary and sets it as an
        instance variable.
        """
        self.message = self.converter.to_bin(string, hexstring)

    def _permute_with(self, string, permutation):
        """
        Permutates each 'bit' of the input string according to the given
        permutation array.
        """
        return ''.join([string[i-1] for i in permutation])

    def f(self, r, k):
        """
        'f' Cipher function
        """
        # Permutation of the R argument against E.
        e = BinString(self._permute_with(r, self.E))
        _k = BinString(k)

        # Bitwise XOR of K and the permutation of R
        k_xor_e = _k ^ e

        # The resulting array will be sliced in 8 groups of 6 bits.
        S = ''
        blocks = self._group_by(k_xor_e, 6)

        for n in range(8):
            # For each group a position for the S tables will be calculated.
            # The row will be the decimal value of the first and last bits of
            # the group together. (0 - 3)
            i = int(blocks[n][0] + blocks[n][-1], 2)

            # The column will be the decimal value of the remaining bits of the
            # group. (0 - 15)
            j = int(blocks[n][1:-1], 2)

            # The value found into the tables will be converted to binary and
            # added to the resulting array.
            S += bin(self.S[n][i][j])[2:].zfill(4)

        # Finally returning the value of the result permuted against P
        return BinString(self._permute_with(S, self.P))

    def __init__(self, converter=BinasciiConverter, **kwargs):
        """
        Class construction, can receive a StringConverter and a key to be
        initialized in unicode or hexadecimal format.
        """
        self.converter = converter
        if kwargs.get('key'):
            self._set_key(kwargs['key'], kwargs.get('hexkey', False))

    def encrypt(self, string, **kwargs):
        """Main DES Cipher algorithm."""

        # We start setting our key if given and the message, we verify the
        # need to convert the input strings to hexadecimal digits (when those
        # parameters are set to False).
        if kwargs.get('key'):
            self._set_key(kwargs['key'], kwargs.get('hexkey', False))
        self._set_message(string, kwargs.get('hexstring', False))

        # A 64 bit key is mandatory to continue.
        assert len(self.key) > 0, 'No input key to perform encryption'
        self._validate_length(self.key, 64)

        # First step: Generation of the sub-keys:

        # Permutation of the key against PC-1.
        pc1_key = self._permute_with(self.key, self.PC_1)

        # Then we split our permutated key in two 28 bits parts.
        C = [BinString(pc1_key[:28])]
        D = [BinString(pc1_key[28:])]

        # And we selectively shift the last generated key pair starting from
        # the split ones and repeating the process 16 times.
        for i in range(16):
            shift = 1 if i in (0, 1, 8, 15) else 2
            C.append(C[-1] << shift)
            D.append(D[-1] << shift)

        # Our sub-keys will be the concatenation of each of the shifted pairs
        # being permuted against PC-2.
        K = []
        for i in range(16):
            CD = C[i+1] + D[i+1]
            K.append(self._permute_with(CD, self.PC_2))

        # The only difference between encryption and decryption is the order of
        # the sub-keys.
        if kwargs.get('decrypt'):
            K = list(reversed(K))

        # Second Step: Message encryption.

        result = ''

        # Iterating over message slices of 64 bits each.
        for block in self._group_by(self.message, 64):
            # Permutation of the message block against PI.
            PI = self._permute_with(block, self.PI)

            # Then split the permutation in two groups of 32 bits.
            L = [BinString(PI[:32])]
            R = [BinString(PI[32:])]

            # And we chain our transformations, consisting of:
            for i in range(16):
                # Passing one group to the opposite next without altering it.
                Ln = R[-1]

                # Transform the other group XORing the last opposite value with
                # the result of the 'f' function over the last value and a
                # subkey.
                Rn = L[-1] ^ self.f(R[-1], K[i])

                # Stack the results for the next iteration.
                L.append(Ln)
                R.append(Rn)

            # At the end of the transformation chain, we'll end with a pair of
            # bit arrays that will be the ciphered block when concatenated and
            # permutated against PI^-1.
            RL = R[-1] + L[-1]
            result += self._permute_with(RL, self.PI_1)

        # Finally, we return our results according to the requested format.
        return self.converter.from_bin(result,
                                       hexstring=kwargs.get('hexresult', False))

    def decrypt(self, string, **kwargs):
        """DES Decryption algorith. See the encryption algorith for details."""
        return self.encrypt(string, decrypt=True, **kwargs)


def crack2DES(plaintext,criptograma,kbits):
	start_time = time.time()
	keyList=[]
	lista_z1=[]
	lista_z2=[]

	if kbits == 16:
		padd=0xffffffffffff0000
	if kbits == 20:
		padd=0xfffffffffff00000
	if kbits == 24:
		padd=0xffffffffff000000
	if kbits == 28:
		padd=0xfffffffff0000000
	if kbits == 32:
		padd=0xffffffff00000000

	print("Plaintext: ", plaintext)
	print("Criptograma: ", criptograma)
	print("K bits: ", kbits)
	print("Loop for + encrypt",pow(2,kbits))
	#Criar lista de chaves Criar lista z1_dict
	z1_dict = {}


	dk=0b0000000100000001000000010000000100000001000000010000000100000001
	#dk="{0:b}".format(17)
	#r=bin(dk|0b1111)
	#print(r,len(str(r)))
	#exit()

	iFull=0
	iSmall=0
	#kbits=24
	for x in range(0,pow(2,kbits)):
		iFull+=1
		#x=int(x)|dk
		#print(bin(x+padd|dk))
		k="{:#04x}".format(x+padd)
		#print(bin(int(x)),len(str(bin(int(x)))),str(x),len(str(x)),"LEN::::::S:")
		
		k=str(k)[2:]
		#print(bin(int(k,16)),"----")
		keyList.append(k)


	print("i_full:",iFull)
	print("time --- %s seconds ---" % (time.time() - start_time))
	keyList=list(set(keyList))
	for k in keyList:
		iSmall+=1
		des = DES()
		cipher = des.encrypt(plaintext, hexstring=True, key=k, hexkey=True, hexresult=True)#'133457799BBCDFF1'
		z1_dict[cipher]=k
	print("i_small:",iSmall)
	print("time --- %s seconds ---" % (time.time() - start_time))
	print("Sao poupados: ",str(int(iFull-iSmall)),"ciclos")
	

	#Verificar z1_dict com decipher
	print("	Criptograma 	K2->Z2		K1->Z1")
	for k in keyList:
		des = DES()
		decipher = des.decrypt(criptograma, hexstring=True, key=k, hexkey=True, hexresult=True)
		if decipher in z1_dict:
			print(" ",decipher," ",k,z1_dict[decipher])
			print("time --- %s seconds ---" % (time.time() - start_time))

	########END PROGRAM
	print("time --- %s seconds ---" % (time.time() - start_time))


if __name__ == '__main__':
	"""
	16-2DES
	(0x31eec97938d99c50,0x59304608429232bb)
	(0x5388917e5f4cca07,0xdfc4635c94051d7c)
	
	20-2DES
	(0x2a2cdb2d409d01a0,0xaa088f298f184d30)
	(0xf5f5639a8290780d,0xde83e23280a9dd86)
	
	24-2DES
	(0x7285627dea7f144d,0xfc07a5ec61463b40)
	(0x316e81b9a532ada5,0x210302fab2c3f1a8)
	
	28-2DES
	(0x9dc5263c4e79c20e,0xe9de3e9db4458c33)
	(0x6d5d558da9ccfc76,0x4c8791b82b3fcc5b)
	
	32-2DES
	(0xf562b7c0aad150a0,0x2e8eedfc53038055)
	(0x39a31fa47ef8e6e3,0x56f211c183de630c)
	"""

	import itertools
	import time

	print()
	print("=======================================================")
	print("|        DES V07 Crack n bits key                     |")
	print("|  Pedro D.  -   Samuel F.       Cripto2018           |")
	print("=======================================================")

	#"Test enc dec"
	"""
	des = DES()
	cipher = des.encrypt('f5f5639a8290780d', hexstring=True, key='fffffffffff143a5', hexkey=True, hexresult=True)
	cipher2 = des.encrypt(cipher, hexstring=True, key='fffffffffffc3c96', hexkey=True, hexresult=True)
	print(cipher2)

	decipher = des.decrypt('de83e23280a9dd86', hexstring=True, key='fffffffffffc3c96', hexkey=True, hexresult=True)
	decipher2 = des.decrypt(decipher, hexstring=True, key='fffffffffff143a5', hexkey=True, hexresult=True)
	print(decipher2)
	"""
	
	crack2DES('31eec97938d99c50','59304608429232bb',16)
	crack2DES('5388917e5f4cca07','dfc4635c94051d7c',16)
	#crack2DES('2a2cdb2d409d01a0','aa088f298f184d30',20)
	#crack2DES('f5f5639a8290780d','de83e23280a9dd86',20)
	
	#crack2DES('7285627dea7f144d','fc07a5ec61463b40',24)
	#crack2DES('316e81b9a532ada5','210302fab2c3f1a8',24)
	#crack2DES('9dc5263c4e79c20e','e9de3e9db4458c33',28)
	#crack2DES('6d5d558da9ccfc76','4c8791b82b3fcc5b',28)
	#crack2DES('f562b7c0aad150a0','2e8eedfc53038055',32)
	#crack2DES('39a31fa47ef8e6e3','56f211c183de630c',32)

	#exit()
