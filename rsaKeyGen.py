from random import randrange, getrandbits

def powmod(x,a,m):
    r=1
    while a>0:
        if a%2==1:
            r=(r*x)%m
        a=a>>1
        x=(x*x)%m
    return a
	
"""
Retorna um par de x,y tal que xa+yb=mdc(a,b)
IN:
    int a, b
OUT:
    int x0, y0
"""
def extended_mdc(a, b):
    x1, x0, y1, y0 = 0, 1, 1, 0
    while b != 0:
        q, r = divmod(a, b) #Fazer divisao com quociente(q) e resto(r)
        a, b = b, r
        x1, x0 = x0 - q * x1, x1
        y1, y0 = y0 - q * y1, y1
    return x0, y0

"""
Inverso Multiplicativo mod(n) 
Retorna d tal que d=e^(-1)
Procurar caso d seja negativo
IN:
    int e,phi
OUT:
    int d
"""
def inv_multiplicativo(e, n): #retornar contante de multiplica e
    x, y = extended_mdc(e, n)
    if x < 0: #Se d < 0: mod(n)
        x=n + x
        return x
    return x

##Miller-Rabin
"""
Testar probablisticamente (com probabilidade de (1/4)^Tentativas) a primalidade de n.
IN:
    int n, k
OUT:
    True/False 
"""
def se_primo(n, t):
    if n % 2 == 0: #Verf. se par
        return False
    # encontra r e s
    s = 0
    r = n - 1
    while r & 1 == 0: #n-1 = (2^s) * r #Testa enquato r e par
        s += 1
        r //= 2
    for _ in range(t): #repete t testes
        a = randrange(2, n - 1) #a aleatorio entre   2 e (n - 1)
        y = pow(a, r, n) #Teste de n composto
        if y != 1 and y != n - 1:
            j = 1
            while j < s and y != n - 1:
                y = pow(y, 2, n)
                if y == 1:
                    return False #nao e primo
                j += 1
            if y != n - 1:
                return False #nao e primo
    return True #provavel primo

"""
Retornar numero pseudo-aleatorio
IN:
    int nbits
OUT:
    int k
"""
def gerar_numero(nbits):
    #geram bits aleatorios de comprimento nbits
    k = getrandbits(nbits)
    #mascar nbits com 1xxxxx1 (OR)
    #Garantir que k seja impar e de ordem de grandeza nbits
    k |= (1 << nbits - 1) | 1
    return k

"""
Retorna um numero primo
IN:
    int nbits 
OUT:
    int numero primo + Print: ntentativas
"""
def numPrimo(nbits):
    p = gerar_numero(nbits)
    #pede novo aleatorio enquanto nao primo
    while not se_primo(p, 128): #parametro de seguranca pruposto: 128 ciclos
        p = gerar_numero(nbits)
    return p

"""
Retorna uma chave para RSA
IN:
    int nbits 
OUT:
    n,p,q,e,d
"""
def genRSAkey(c):
    e=65537 #pow(2,16)+1
    p=numPrimo(c)
    print("-")#Apagar esta linha
    q=numPrimo(c)
    while q == p: #Garantir que q != p
        q = numPrimo(c)
    print("-")#Apagar esta linha
    n=p*q
    phi = (p - 1) * (q - 1) 
    d = inv_multiplicativo(e, phi)
    return n,p,q,e,d

#Call da funcao genRSAkey(l)
n, p, q, e, d = genRSAkey(1024) #Demora 10seg em media a calcular

print("n:",n)
print("p:",p)
print("q:",q)
print("e:",e)
print("d:",d)

print("----------------------------")
