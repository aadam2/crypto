# -*-coding:utf-8 -*

import os
from bitstring import BitArray
import hashlib
import ast
import time
import random
import pickle
import codecs

# Generic functions
def tobits(s): # Converts characters into a list of bits
    result = []
    for c in s:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        result.extend([int(b) for b in bits])
    return result

def frombits(bits): # Converts a list of bits into characters
    chars = []
    for b in range(len(bits) / 8):
        byte = bits[b*8:(b+1)*8]
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
    return ''.join(chars)


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m
    
#sauvegarde des clés, avec un pickle (dictionnaire)
def storekeys(c,d,h,g1,g2,q,x1,x2,y1,y2,z,timestamp):
    currentpath = getscriptpath
    if not os.path.isdir(currentpath + "/cramershoup/"):
        os.mkdir(currentpath + "/cramershoup")    
    
    if not os.path.isdir(currentpath + "/cramershoup/publickeys_cs"):
        os.mkdir(currentpath + "/cramershoup/cypheredmsgs")
    if not os.path.isdir(currentpath + "/cramershoup/privatekeys_cs"):
        os.mkdir(currentpath + "/cramershoup/cypheredmsgs")    
        
    #Store public and private keys in two separate files, using current timestamp as an identifier
    os.chdir(currentpath + "/cramershoup/publickeys_cs")
    filename = "publickey_"+str(timestamp)+".pblk"
    #print(filename)
    key = {
        "c": c,
        "d": d,
        "h": h,
        "g1": g1,
        "g2": g2,
        "q": q
        }
    with open(filename,'wb') as fichier:
        pickler = pickle.Pickler(fichier)
        pickler.dump(key)
    
    
    os.chdir(currentpath + "/cramershoup/privatekeys_cs")
    filename = "privatekey_"+str(timestamp)+".prvk"
    #print(filename)
    key = {
        "x1": x1,
        "x2": x2,
        "y1": y1,
        "y2": y2,
        "z": z
        }
    with open(filename,'wb') as fichier:
        pickler = pickle.Pickler(fichier)
        pickler.dump(key)



#récupération de la clé publique avec le nom du fichier
def restorepublickey(filename):
    currentpath = getscriptpath()

    os.chdir(currentpath + "/cramershoup/publickeys_cs")
    listparam = []
    with open(filename, 'rb') as key:
        depickler = pickle.Unpickler(key)
        key = depickler.load()
        for value in key.values():
            #print(value)
            listparam.append(value)
    return listparam    
  

# Write a number as a sum of powers of 2
def decompose(e):
    binaryList = []
    powerList = []

    q = 1 # Giving q a value, so it can bound the first time

    while q != 0:
        # Quotient and remainder
        q = e / 2
        r = e % 2

        binaryList.append(r)

        e = e / 2

    # Now populating the power list
    bitPos = 0
    for bit in binaryList:
        if bit == 1:
            powerList.append(2**bitPos)
        bitPos += 1

    return powerList

# Computing a^(e) mod m
def computeModuleWithExpoBySquaring(a, e, m):
    modList = []
    currentPower = 1
    actualPower = 1
    currentMod = a
    # First step : writing e as the sum of powers of 2
    powerList = decompose(e)
    maxPower = max(powerList)
    while currentPower <= maxPower:
        currentMod = currentMod ** actualPower % m
        if currentPower in powerList:
            modList.append(currentMod)
        currentPower = currentPower * 2
        actualPower = 2

    listProduct=1
    for mod in modList:
        listProduct = listProduct*mod

    return listProduct % m
  
def miller_rabin(n, k):
    if n == 2:
        
        return True
    if n%2 == 0:
        return False
    if not n & 1:
      
        return False

    def check(a, s, d, n):
        x = pow(a, d, n)
        if x == 1:
            return True
        for i in range(s - 1):
            if x == n - 1:
                return True
            x = pow(x, 2, n)
        return x == n - 1

    s = 0
    d = n - 1

    while d % 2 == 0:
        
        d >>= 1
        s += 1

    for i in range(k):
    
        a = random.randrange(2, n - 1)
        
        if not check(a, s, d, n):
         
            return False
  
    return True
        

def hashtxt(textmsg,filename):
    
    currentpath = getscriptpath()
    if not os.path.isdir(currentpath + "/hashsGS15/"):
        os.mkdir(currentpath + "/hashsGS15")     
    stringencoded = bytes(codecs.encode(textmsg))
    hashfinal = hashlib._hashlib.openssl_sha256(stringencoded).hexdigest()
    
    filenamefinal = "hash_"+filename+".hashgs15"
    os.chdir(currentpath + "/hashsGS15")
    filetosave = open(filenamefinal,'wt')
    filetosave.write(hashfinal)
    filetosave.close()
    
    return [hashfinal,filenamefinal]
    
    
def hashfile(filepath):
    currentpath = getscriptpath()
    if not os.path.isdir(currentpath + "/hashsGS15"):
        os.mkdir(currentpath + "/hashsGS15")    
    splitpath = filepath.split("/")
    filename = splitpath.pop()
    
    stringfile = ""
    textfile = open(filepath,'rt')
    for line in textfile:
        stringfile = stringfile + line
    textfile.close()
            
    stringencoded = bytes(codecs.encode(stringfile))
    hashfinal = hashlib._hashlib.openssl_sha256(stringencoded).hexdigest()
    
    filenamefinal = "hash_"+filename+".hashgs15"
    os.chdir(currentpath + "/hashsGS15")
    filetosave = open(filenamefinal,'wt')
    filetosave.write(hashfinal)
    filetosave.close()
    
    return [hashfinal,filenamefinal]
    
            
def verifhash_file(filepath, hashfiletocheck):
    hashtocheck = hashfile(filepath)
    hashtxt = ""
    hashfile = open(hashfiletocheck,'rt')
    for line in hashfile:
        hashtxt = hashtxt + line
    hashfile.close()
    print(hashtocheck+"\n"+hashtxt)
    return hashtocheck == hashtxt
    
def verifhash_txt(msgtocheck, hashfiletocheck):
    hashtxt = ""
    hashfile = open(hashfiletocheck,'rt')
    for line in hashfile:
        hashtxt = hashtxt + line
    hashfile.close()
    hashtocheck = hashlib._hashlib.openssl_sha256(stringencoded).hexdigest()
    print(hashtocheck+"\n"+hashtxt)
    return hashtocheck == hashtxt
    
    
    
#On récupère la clé privée de la même façon
def restoreprivatekey(filename):
    currentpath = getscriptpath()
    os.chdir(currentpath + "/cramershoup/privatekeys_cs")
    listparam = []
    with open(filename, 'rb') as key:
        depickler = pickle.Unpickler(key)
        key = depickler.load()
        for value in key.values():
            #print(value)
            listparam.append(value)
    return listparam               
       
def cypherfile_cramershoup(filepath,key,timestamp):
    filetexttocypher = ""
    filetocypher = open(filepath,'rt')
    filetexttocypher = filetocypher.read()
    #for line in filetocypher:
        #filetexttocypher = filetexttocypher + line + "\n"
    filetocypher.close()
  
    print(filetexttocypher)
    return cypher_cramershoup(filetexttocypher,key,timestamp)
        

#fonction de chiffrement, demandant le message, la clé publique et le timestamp. On pourra éventuellement insérer la génération des clés dans cette fonction.
def cypher_cramershoup(msg,key,timestamp):
    
    #la clé est fournie grâce à la fonction keygen() qui renvoie un tableau contenant les données
    #print("c = ",key[0])
    #print("d = ",key[1])
    #print("h = ",key[2])
    #print("g1 = ",key[3])
    #print("g2 = ",key[4])
    #print("q = ",key[5])
    
    c = key[0]
    d = key[1]
    h = key[2]
    g1 = key[3]
    g2 = key[4]
    q = key[5]
    
    k = random.randint(0,2**512-1)
    #print("k = ",k)
    kstatic = k
    
    u1 = computeModuleWithExpoBySquaring(g1,k,q)
    u2 = computeModuleWithExpoBySquaring(g2,k,q)
    hk = computeModuleWithExpoBySquaring(h,k,q)
    
    
    
    #On récupère les valeurs de u1 et u2 sous forme de chaîne hexadécimale, pour les réutiliser dans la fonction de hachage
    bitstru1 = hex(u1)
    bitstru2 = hex(u2)
    stru1 = str(bitstru1)[2:]
    stru2 = str(bitstru2)[2:]
    
    
    
    #print("u1 = ",u1)
    #print("u2 = ",u2)
    #print("h^k = ",hk)
    
    
    #On sépare en blocs de 256 bits --> 32 caractères. Ainsi, le nombre correspondant au message sera au plus égal à 2^255 - 1, et on est sur qu'il sera dans Zq avec q un entier de 512 bits.
    totallength = len(msg)
    #print (totallength)
    nbblocks = 0
    if totallength%8 == 0:
        nbblocks = totallength//32
    else:
        nbblocks = totallength//32 + 1
    print(str(nbblocks) + "blocs")
    listblocks=[]
    for i in range(nbblocks):
        blockarr = []
        listblocks.append(blockarr)
    for i in range(totallength):
        chara = msg[i]
        blocktofill = i//32
        posinblock = i%32
        print(chara+";"+str(blocktofill)+";"+str(posinblock))
        listblocks[blocktofill].insert(posinblock, chara)
    listcypheredblock10 = []
    listverifhashs = []
    for block in listblocks:
        blockinbase10 = 0
        #print(block)
        blockarray = []
        
        #on convertit les caractères en binaire
        for chara in block:
            for bit in tobits(chara):
                blockarray.append(bit)
        #on récupère la valeur du nombre binaire ainsi formé
        blockinbase10 = BitArray(blockarray)._getint()
       
        print("MESSAGE BLOCK = ",hex(blockinbase10))
        e = hk*blockinbase10
        
        #print ("E = ",e)
        bitstre = hex(e)
        
        print("CYPHEREDHEX = ", bitstre)
        stre = str(bitstre)[2:]
        
        print("CYPHEREDMSG = ", stre)
        
        
        listcypheredblock10.append(bitstre)
        
        #fonction de hachage qui servira à la vérification (c'est là que ça foire :/)
        stringcyphered = bytes(codecs.encode(stre))
        stringu1 = bytes(codecs.encode(stru1))
        stringu2 = bytes(codecs.encode(stru2))
        #print("STRINGCYPHERED = ",stringcyphered, " -- STRINGU1 = ",stringu1," -- STRINGU2 = ",stringu2)
        
        
        hashmsg = hashlib._hashlib.openssl_sha256(stringcyphered+stringu1+stringu2).hexdigest()
        alpha = int(hashmsg,16)
        
        #print("STRE = ",stre, "; STRU1 = ",stru1," ; STRU2 = ",stru2)
        #print("\n ALPHA = ",alpha,"\n")
        
        expka = k*alpha % q
        #print(c,";",k,";",q,";",d,";",alpha,";",q)
        ck = computeModuleWithExpoBySquaring(c,k,q)
        dk = computeModuleWithExpoBySquaring(d,k,q)
        dkalpha = computeModuleWithExpoBySquaring(dk,alpha,q)
        v = ck * dkalpha %q
        
       # print("v = ",v)
        #print(hex(v))
        strv = str(hex(v))[2:]
        listverifhashs.append(strv)
        #print("ck = ",computeModuleWithExpoBySquaring(c,k,q))
        #print("dk = ",computeModuleWithExpoBySquaring(d,k,q))
        dk = computeModuleWithExpoBySquaring(d,k,q)
        #print("dkalpha = ",computeModuleWithExpoBySquaring(dk,alpha,q))        
    stringtosavemsg = ""
    stringtosavehash = ""
    for strmsg in listcypheredblock10:
        stringtosavemsg = stringtosavemsg + strmsg + "//"
    for strhash in listverifhashs:
        stringtosavehash = stringtosavehash + strhash + "//"
        
    #on sauvegarde grâce à la fonction savecypheredmsg() qui renvoie le nom du fichier
    filename = savecypheredmsg(stru1,stru2,stringtosavemsg,stringtosavehash,timestamp)
    
   
    return filename
    
        
# Functions definitions
def computeGCD(a, b):
    if b == 0:
        return a
    return computeGCD(b, a % b)

# Computing a^(-1) mod p
def computeModInv(a, p):
    if computeGCD(a, p) != 1:
        raise Exception("Modular inverse does not exist")

    originalP = p # Saving the orinal modulo

    x0 = 1
    x1 = 0
    y0 = 0
    y1 = 1

    i = 0 # Debug

    while p != 0:
        i += 1
        # Quotient and remainder
        q = a / p
        r = a % p

        #print("q and r at round {0} : q = {1} and r = {2}".format(i, q, r))

        # Computing GCD
        a = p
        p = r

        if p != 0 :
         #   print("#############################################")
          #  print("All parameters at round {4} before calculations : x0 = {0}, x1 = {1}, y0 = {2}, y1 = {3}".format(x0, x1, y0, y1, i))
            # Extented Euclid's algorithm X and Y
            tempX = x1
            x1 = x1 * q + x0
            x0 = tempX # Updating for the potential next round
            tempY = y1
            y1 = y1 * q + y0
            y0 = tempY # Updating for the potential next round
          #  print("All parameters at round {4} after calculations : x0 = {0}, x1 = {1}, y0 = {2}, y1 = {3}".format(x0, x1, y0, y1, i))
           # print("#############################################")

   # print("All parameters at the end : x0 = {0}, x1 = {1}, y0 = {2}, y1 = {3}".format(x0, x1, y0, y1))

    if (i%2 != 0):
        x1 = -x1

   # print("Computed modular inverse : {0}".format(x1))
    if x1 < 0:
        x1 = x1 % originalP
        print("Modular inverse made positive : {0}".format(x1))

    returnvalue = 0
    
    if x1-int(x1)>0.5:
        returnvalue = int(x1+1)
    else:
        returnvalue = int(x1)
    return returnvalue

        
  
    
def savecypheredmsg(u1,u2,cypheredblockstring,cypheredhashstring,timestamp):
    currentpath = getscriptpath()
    os.chdir(currentpath + "/cramershoup")
    if not os.path.isdir(currentpath + "/cramershoup/cypheredmsgs"):
        os.mkdir(currentpath + "/cramershoup/cypheredmsgs")
    os.chdir(currentpath + "/cramershoup/cypheredmsgs")
    filename = "cypheredmsg_"+str(timestamp)+".cymsg"
    file = open(filename, "wt")
    file.write(str(u1)+"\n")
    file.write(str(u2)+"\n")
    file.write(cypheredblockstring+"\n")
    file.write(cypheredhashstring)
    file.close()
    return filename

def decypher_cramershoup(msgfilename):
    
    currentpath = getscriptpath()
    #On isole le timestamp pour retrouver les fichiers des clés
    os.chdir(currentpath + "/cramershoup/cypheredmsgs")
    timestampinter = msgfilename.split("_")
    timestamp = timestampinter[1].split(".")[0]
    filetoopen = open(msgfilename)
    data = []
    for line in filetoopen:
         
        data.append(line)
    
    
    
    u1 = data[0]
    u2 = data[1]
    e = data[2]
    v = data[3]
    
    privatekeyname = "privatekey_"+timestamp+".prvk"
    publickeyname = "publickey_"+timestamp+".pblk"   
    
   
    
    
    #On récupère les clés
    key = restoreprivatekey(privatekeyname)
    keypb = restorepublickey(publickeyname)
    
    x1 = key[0]
    x2 = key[1]
    y1 = key[2]
    y2 = key[3]
    z = key[4]
    
    h = int(keypb[2])
    g1 = int(keypb[3])
    g2 = int(keypb[4])
    
    q = int(keypb[5])
    
    
    
    #on avait séparé les blocs dans le message stocké en ajoutant des //
    arraye = e.split("//")
    arraye.pop()
    arrayv = v.split("//")
    arrayv.pop()
    
    i = 0
    
    numberu1 = int(u1,16)
    numberu2 = int(u2,16)
    
    numberx1 = int(x1)
    numberx2 = int(x2)
    
    numbery1 = int(y1)
    numbery2 = int(y2)
    
    #print("x1 = ",numberx1)
    #print("x2 = ",numberx2)
    #print("y1 = ",numbery1)
    #print("y2 = ",numbery2)
    #print("g1 = ",g1)
    #print("g2 = ",g2)    
    
    numberz = int(z)
    
    stringu1 = bytes(codecs.encode(u1[:-1]))
    stringu2 = bytes(codecs.encode(u2[:-1]))
    
    booleanverif = True
    
    for ei in arraye:
        print("ei = ",ei)
    for ei in arraye:
        numbere = int(ei,16)
        numberv = int(arrayv[i],16)
        stringcyphered = bytes(codecs.encode(ei[2:]))
        
        #print("STRE = ",ei[2:], "; STRU1 = ",u1," ; STRU2 = ",u2)

        #print("STRINGCYPHERED = ",stringcyphered, " -- STRINGU1 = ",stringu1," -- STRINGU2 = ",stringu2)
        
        #on calcule le hash pour chaque bloc et on vérifie qu'il est égal au hash stocké
        hashmsg2 = hashlib._hashlib.openssl_sha256(stringcyphered+stringu1+stringu2).hexdigest()
        alpha = int(hashmsg2,16)
        
       # print("\n ALPHA = ",alpha,"\n")
        
        verif2int = (computeModuleWithExpoBySquaring(numberu1,numbery1,q)*computeModuleWithExpoBySquaring(numberu2,numbery2,q))%q
        verifpt1 = (computeModuleWithExpoBySquaring(numberu1,numberx1,q)*computeModuleWithExpoBySquaring(numberu2,numberx2,q))
        verifpt2 = computeModuleWithExpoBySquaring(verif2int,alpha,q)
       # print("VERIF PT1 = ",(computeModuleWithExpoBySquaring(numberu1,numberx1,q)*computeModuleWithExpoBySquaring(numberu2,numberx2,q)) % q)
        #print("VERIF PT2 = ", computeModuleWithExpoBySquaring(verif2int,alpha,q))
        
        verif = (verifpt1 * verifpt2) %q
       # print("verif = ",verif)
        #print("numberv = ",numberv)
        if verif != numberv: 
            booleanverif = False
            break
        i+=1
    
    if not booleanverif:
        #print("La vérification est fausse : déchiffrement annulé")
        return("NULL")
    else:
        
        #si le hash est valide : on déchiffre chaque bloc puis on retourne le tableau des blocs déchiffrés
        arraymsg = []
        u1z = computeModuleWithExpoBySquaring(numberu1,numberz,q)
        print("u1z = ",u1z)
        
     
        msgtotal = ""
    
        invu1z = modinv(u1z,q)
        for ei in arraye:
            msgblck = []
            numbere = int(ei,16)
            
            print("HEX MSG = ",hex(numbere))
            m = numbere*invu1z % q
            
            strm = str(hex(m))[2:]
            
            print("MESSAGE  = ",strm)
            for i in range(len(strm)//2):
                charinhex = strm[2*i]+strm[2*i+1]
                character = chr(int(charinhex,16))
                msgblck.append(character)
            arraymsg.append(msgblck)
            
            print(msgblck)
            for c in msgblck:
                msgtotal = msgtotal + c
            
        return msgtotal
    
                
            
            
            
        
        

#Génération de la clé grâce au timestamp
def keygen_cramershoup(timestamp):
    publickeyarray = []
    q = 0
    while not miller_rabin(q,100):
        q = random.randint(2**511,2**512-1)
   # print("On travaille dans Z",q)
    g1=0
    g2=0
    while not miller_rabin(g1,100):
        g1 = random.randint(0,q-1)
    while not miller_rabin(g2,100):
        g2 = random.randint(0,q-1)
   # print("Les générateurs sont ",g1," et ",g2)
    x1 = random.randint(0,q-1)
    x2 = random.randint(0,q-1)
    y1 = random.randint(0,q-1)
    y2 = random.randint(0,q-1)
    z = random.randint(0,q-1)
  #  print("x1 = ",x1)
    #print("x2 = ",x2)
    #print("y1 = ",y1)
    #print("y2 = ",y2)
    #print("g1 = ",g1)
    #print("g2 = ",g2)
    #print("z = ",z)
    
    c = (computeModuleWithExpoBySquaring(g1,x1,q)*computeModuleWithExpoBySquaring(g2,x2,q))%q
    #print("c = ",c)
    d = (computeModuleWithExpoBySquaring(g1,y1,q)*computeModuleWithExpoBySquaring(g2,y2,q))%q
    #print("d = ",d)
    h = computeModuleWithExpoBySquaring(g1,z,q)
    #print("h = ",h)
    
    publickeyarray.append(c)
    publickeyarray.append(d)
    publickeyarray.append(h)
    publickeyarray.append(g1)
    publickeyarray.append(g2)
    publickeyarray.append(q)
    
    storekeys(c,d,h,g1,g2,q,x1,x2,y1,y2,z,timestamp)
    return publickeyarray
    
def gettimestamp():
    return int(time.time())

def contains(small, big): # Check if the elemets contained in the list "small" are also contained in the list "big"
    for i in xrange(len(big)-len(small)+1):
        for j in xrange(len(small)):
            if big[i+j] != small[j]:
                break
        else:
            return True
    return False

def open_file(filename, block_size): # Block size is given in bytes
    file_bits = []
    with open(filename, "rb") as binary_file:
        i = 1
        # Seek position and read block_size bytes at the time
        file_size = os.stat(filename).st_size
        binary_file.seek(0)
        current_cursor_position = 0
        while (current_cursor_position + block_size) < file_size :
            bytes_block = binary_file.read(block_size)

            # Adding the bits
            bits = tobits(bytes_block)
            file_bits.append(bits)

            current_cursor_position += block_size
            binary_file.seek(current_cursor_position)
            i += 1
            if (current_cursor_position + block_size) >= file_size :
                bytes_block = binary_file.read(file_size%block_size) # Reading the remaining characters
                # Adding the last bits
                bits = tobits(bytes_block)
                file_bits.append(bits)

        print("Done.")

    file_bits = merge_list_of_lists(file_bits)
    return file_bits

def alt_open_file(filename, block_size): # Opens all the file at once
    file_bits = []
    with open(filename, "rb") as binary_file:
        i = 1
        # Seek position and read block_size bytes at the time
        file_size = os.stat(filename).st_size
        binary_file.seek(0)
        current_cursor_position = 0

        bytes_block = binary_file.read(file_size)

        # Adding the bits
        bits = tobits(bytes_block)
        file_bits.append(bits)


    file_bits = merge_list_of_lists(file_bits)
    return file_bits

def write_bits_to_file(filename, bitlist):
    enc_msg_str = ', '.join(map(str, bitlist))
    with open(filename, 'w+') as f: # Create a file if it doesn't already exist
        # Write to the file
        f.write("[{0}]".format(enc_msg_str))
        # Close the connection to the file
        f.close()

def write_text_to_file(filename, text):
    with open(filename, 'w+') as f: # Create a file if it doesn't already exist
        # Write to the file
        f.write(text)
        # Close the connection to the file
        f.close()

def read_file_content(filename):
    with open(filename, 'r') as content_file:
        content = content_file.read()
    content_list = ast.literal_eval(content)
    return content_list

def bitfield(n): # Converts integer to bit list
    return [int(digit) for digit in bin(n)[2:]] # [2:] to chop off the "0b" part

def make_list_64_bits_long(bits_list):
    while len(bits_list) < 64:
        bits_list.insert(0, 0)
    return bits_list

def divide_list(bits_list, num): # Used to generate equal size sublists, may for example be used to generate subkeys
    avg = len(bits_list) / float(num)
    out = []
    last = 0.0

    while last < len(bits_list):
        out.append(bits_list[int(last):int(last + avg)])
        last += avg

    return out

def alt_divide_list(bits_list, num, block_size): # Used to generate equal size sublists, may for example be used to generate subkeys
    # Completing as necessary
    while (len(bits_list) % block_size) != 0:
        bits_list.append(0)
    avg = len(bits_list) / float(num)
    out = []
    last = 0.0
    while last < len(bits_list):
        out.append(bits_list[int(last):int(last + avg)])
        last += avg
    return out

def merge_list_of_lists(l):
    flat_list = [item for sublist in l for item in sublist]
    return flat_list

def xoring_two_lists(list_A, list_B):
    xored_list = []
    list_size = len(list_A)
    for i in range(list_size):
        xored_list.append(list_A[i] ^ list_B[i])
    return xored_list

def generate_initialization_vector(size):
    iv = []
    for i in range(size):
        iv.append(1)
    return iv

def xoring_list_of_lists(subkeys_list):
    nb_lists = len(subkeys_list)
    last_subkey = subkeys_list[0]
    for i in range(1, nb_lists):
        last_subkey = xoring_two_lists(last_subkey,subkeys_list[i])

    C = [0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0]
    last_subkey = xoring_two_lists(last_subkey, C)
    return last_subkey

def modular_addition(list_A, list_B): # Takes lists of bits as input([1, 0, 0, 1] for example), does the addtion mod 2^64
    a = BitArray(list_A)
    b = BitArray(list_B)

    mod_sum = bin(int(a.bin, 2) + int(b.bin,2))
    mod_sum = mod_sum[2:] # [2:] to chop off the "0b" part

    mod_sum_list = []
    for i in range(0, len(mod_sum)):
        mod_sum_list.append(mod_sum[i])

    mod_sum_list = [int(x) for x in mod_sum_list] # Converting list elements to int

    while len(mod_sum_list) < 64:
        mod_sum_list.insert(0, 0)

    if len(mod_sum_list) > len(list_A): # Removing the last element if necessary
        mod_sum_list.pop(0)

    return mod_sum_list

def binary_sub(list_A, list_B): # Computes binary substraction ; list_A shall be greater than list_B
    a = BitArray(list_A)
    b = BitArray(list_B)

    bin_sub = bin(int(a.bin, 2) - int(b.bin, 2))

    if int(bin_sub,2) < 0:
        bin_sub = bin(int(bin_sub, 2) + 2**64)

    bin_sub = bin_sub[2:] # [2:] to chop off the "0b" part

    if (bin_sub[0] == 'b'):
        bin_sub = bin_sub[1:] # To remove the potential b remaining

    bin_sub_list = []
    for i in range(0, len(bin_sub)):
        bin_sub_list.append(bin_sub[i])

    bin_sub_list = [int(x) for x in bin_sub_list] # Converting list elements into int

    while len(bin_sub_list) < len(list_A): # Padding zeros at the beginning if necessary
        bin_sub_list.insert(0, 0)

    return bin_sub_list

def offset_list(l, offset): # Offsets bits to the left
    offsetted_list = []
    for i in range(len(l)):
        offsetted_list.append(l[(i + offset) % len(l)])
    return offsetted_list

def reverse_offset_list(l, offset): # Offsets bits to the right
    reverse_offsetted_list = []
    for i in range(len(l)):
        reverse_offsetted_list.append(l[(i - offset) % len(l)])
    return reverse_offsetted_list

def mix(block):
    # Browsing the block, two words at a time, doing the mixing work
    nb_of_words = len(block) / 64
    block_words_list = divide_list(block, nb_of_words)

    mixed_block = []
    for i in range(0, nb_of_words - 1, 2):
        m1 = block_words_list[i]
        m2 = block_words_list[i+1]

        # Offsetting m2
        offsetted_m2 = offset_list(m2, 49)

        # Doing the mixing stuff
        mixed_m1 = modular_addition(m1, m2)
        mixed_m2 = xoring_two_lists(mixed_m1, offsetted_m2)

        # Appending the words
        mixed_block.append(mixed_m1)
        mixed_block.append(mixed_m2)

    mixed_block = merge_list_of_lists(mixed_block) # To obtain a single list from a list of lists

    return mixed_block

def reverse_mix(block):
    # Browsing the block, two words at a time, doing the mixing work
    nb_of_words = len(block) / 64
    block_words_list = divide_list(block, nb_of_words)

    retrieved_block = []
    for i in range(0, nb_of_words - 1, 2):

        mixed_m1 = block_words_list[i] # m1'
        mixed_m2 = block_words_list[i+1] # m2'

        # Retrieving m2
        offsetted_m2 = xoring_two_lists(mixed_m1, mixed_m2)
        m2 = reverse_offset_list(offsetted_m2, 49)

        # Retrieving m1
        m1 = binary_sub(mixed_m1, m2)

        # Appending the retrieved words
        retrieved_block.append(m1)
        retrieved_block.append(m2)

    retrieved_block = merge_list_of_lists(retrieved_block) # To obtain a single list from a list of lists

    return retrieved_block

def permute(block):
    # Reverses the order of the words that constitute the block (may change in the future)
    return list(reversed(block))


# Functions definitions
# ThreeFish related
def threefish_key_schedule(key, block_size): # Generates the original keywords list

    # Computing the three tweaks
    t0 = key[:64]# First 64 bits from the key
    t1 = key[64:128]# Following 64 bits of the key
    t2 = xoring_two_lists(t0, t1)
    tweaks = []
    tweaks.append(t0)
    tweaks.append(t1)
    tweaks.append(t2)

    # Computing number of keywords
    nb_key_words = block_size / 64
    keywords_list = divide_list(key, nb_key_words)

    # Now adding kN : kN = k0 ^ k1 ^ ... ^ k_N-1 ^ C
    last_subkey = xoring_list_of_lists(keywords_list)

    # Appending the last subkey to the key
    keywords_list.append(last_subkey)

    round_list = []
    rounds_keywords_list = [] # List of lists of lists, keywords list for each round (Round -> Keywords_List -> Keyword)

    N = nb_key_words
    for i in range(76): # Browsing the rounds
        for n in range(N-3): # Browsing the blocks
            round_list.append(keywords_list[(n + i) % (N + 1)])
        round_list.append(modular_addition(keywords_list[(N - 3 + i) % (N + 1)], tweaks[(i % 3)])) # N-3
        round_list.append(modular_addition(keywords_list[(N - 2 + i) % (N + 1)], tweaks[((i + 1) % 3)])) # N-2
        # Convert i to bit array
        i_bitlist = bitfield(i)
        # Make it 64 bits long
        i_bitlist = make_list_64_bits_long(i_bitlist)
        round_list.append(modular_addition(keywords_list[(N - 1 + i) % (N + 1)], i_bitlist)) # N-1 here
        rounds_keywords_list.append(round_list)

    return rounds_keywords_list

def threefish_encrypt(key, msg_bits, block_size):
    # rounds_keywords_list contains all round keys
    rounds_keywords_list = threefish_key_schedule(key, block_size) # Generating the key words
    # rounds_keywords_list[0] : contains the key words list for round 0
    # rounds_keywords_list[0][0] : contains the word 0 of the word list for round 0

    # Computing nb_msg_blocks
    if len(msg_bits) % block_size == 0:
        nb_msg_blocks = len(msg_bits) / block_size
        msg_blocks = divide_list(msg_bits, nb_msg_blocks)
    else:
        nb_msg_blocks = len(msg_bits) / block_size + 1
        msg_blocks = alt_divide_list(msg_bits, nb_msg_blocks, block_size)


    round_number = 0
    block_number = 0
    key_used_times = 0

    encrypted_msg_blocks = [] # May contain 1 or several blocks

    for block in msg_blocks: # Browsing the blocks
        encrypted_block = block

        while len(encrypted_block) < block_size:
            encrypted_block.append(0)

        for round_number in range(76): # Browsing the rounds
        #for round_number in range(1): # Browsing the rounds

            # 1 - Adding the key if necessary
            if (round_number == 0) or ((round_number % 4) == 0) or (round_number == 75): # Need to add key here
                key_used_times += 1
                # Dividing the block into words
                block_words_list = divide_list(encrypted_block, len(encrypted_block)/64)
                encrypted_block_words = []
                for block_word in block_words_list: # Browsing block words
                    #print("Used to ENCRYPT : {0}".format(rounds_keywords_list[round_number][block_number]))
                    encrypted_block_words.append(xoring_two_lists(block_word, rounds_keywords_list[round_number][block_number]))
                encrypted_block = merge_list_of_lists(encrypted_block_words)

            # 2 - Mixing (Substitute)
            encrypted_block = mix(encrypted_block)

            # 3 - Permute
            encrypted_block = permute(encrypted_block)

        encrypted_msg_blocks.append(encrypted_block)
        block_number += 1

    encrypted_msg = merge_list_of_lists(encrypted_msg_blocks)

    return encrypted_msg # Regular ECB encryption mode

def threefish_decrypt(key, msg_bits, block_size):
    # rounds_keywords_list contains all round keys
    rounds_keywords_list = threefish_key_schedule(key, block_size) # Generating the key words
    # rounds_keywords_list[0] : contains the key words list for round 0
    # rounds_keywords_list[0][0] : contains the word 0 of the word list for round 0

    nb_msg_blocks = len(msg_bits) / block_size
    msg_blocks = divide_list(msg_bits, nb_msg_blocks)

    round_number = 0
    block_number = 0
    key_used_times = 0

    decrypted_msg_blocks = [] # Will contain 1 or several blocks

    for block in msg_blocks: # Browsing the blocks
        decrypted_block = block
        for round_number in range(75, -1, -1):
        #for i in range(1):
            #round_number = 75

            # 1 - Reverse permute (same function here)
            decrypted_block = permute(decrypted_block)

            # 2 - Undo mixing
            decrypted_block = reverse_mix(decrypted_block)

            # 3 - Substracting the key if necessary (depending on the round number)
            if (round_number == 0) or ((round_number % 4) == 0) or (round_number == 75): # Need to substract the key here
                key_used_times += 1
                # Dividing the block into words
                block_words_list = divide_list(decrypted_block, len(decrypted_block)/64)
                decrypted_block_words = []
                for block_word in block_words_list: # Browsing the block words
                    #print("Used to DECRYPT : {0}".format(rounds_keywords_list[round_number][block_number]))
                    decrypted_block_words.append(xoring_two_lists(block_word, rounds_keywords_list[round_number][block_number]))
                decrypted_block = merge_list_of_lists(decrypted_block_words)

        decrypted_msg_blocks.append(decrypted_block)
        block_number += 1

    decrypted_msg = merge_list_of_lists(decrypted_msg_blocks)

    return decrypted_msg # Regular ECB decryption mode

def cbc_threefish_encrypt(key, msg_bits, block_size): # CBC encryption mode

    # rounds_keywords_list contains the keys for all the rounds
    rounds_keywords_list = threefish_key_schedule(key, block_size) # Generating the key words
    # rounds_keywords_list[0] : contains the key words list for round 0
    # rounds_keywords_list[0][0] : contains the word 0 of the word list for round 0

     # Computing nb_msg_blocks
    if len(msg_bits) % block_size == 0:
        nb_msg_blocks = len(msg_bits) / block_size
        msg_blocks = divide_list(msg_bits, nb_msg_blocks)
    else:
        nb_msg_blocks = len(msg_bits) / block_size + 1
        msg_blocks = alt_divide_list(msg_bits, nb_msg_blocks, block_size)

    round_number = 0
    block_number = 0
    key_used_times = 0

    encrypted_msg_blocks = [] # May contain 1 or several blocks

    initialization_vector = generate_initialization_vector(block_size)
    previous_encrypted_block = initialization_vector

    for block in msg_blocks: # Browsing the blocks
        encrypted_block = block

        while len(encrypted_block) < block_size:
            encrypted_block.append(0)


        # Xoring with the previous encrypted block
        encrypted_block = xoring_two_lists(encrypted_block, previous_encrypted_block)

        # Doing the Threefish encryption itself
        for round_number in range(76): # Browsing the rounds
        #for round_number in range (1): # Browsing the rounds

            # 1 - Adding the key if necessary
            if (round_number == 0) or ((round_number % 4) == 0) or (round_number == 75): # Need to add key here
                key_used_times += 1
                # Dividing the block into words
                block_words_list = divide_list(encrypted_block, len(encrypted_block)/64)
                encrypted_block_words = []
                for block_word in block_words_list: # Browsing block words
                    #print("Used to ENCRYPT : {0}".format(rounds_keywords_list[round_number][block_number]))
                    encrypted_block_words.append(xoring_two_lists(block_word, rounds_keywords_list[round_number][block_number]))
                encrypted_block = merge_list_of_lists(encrypted_block_words)

            # 2 - Mixing (Substitute)
            encrypted_block = mix(encrypted_block)

            # 3 - Permute
            encrypted_block = permute(encrypted_block)

        encrypted_msg_blocks.append(encrypted_block)
        block_number += 1

    encrypted_msg = merge_list_of_lists(encrypted_msg_blocks)

    return encrypted_msg

def cbc_threefish_decrypt(key, msg_bits, block_size): # CBC decryption mode
    # rounds_keywords_list contains all round keys
    rounds_keywords_list = threefish_key_schedule(key, block_size) # Generating the key words
    # rounds_keywords_list[0] : contains the key words list for round 0
    # rounds_keywords_list[0][0] : contains the word 0 of the word list for round 0

    nb_msg_blocks = len(msg_bits) / block_size
    msg_blocks = divide_list(msg_bits, nb_msg_blocks)

    round_number = 0
    block_number = 0
    key_used_times = 0

    decrypted_msg_blocks = [] # Will contain 1 or several blocks

    # Generating the initialization vector
    initialization_vector = generate_initialization_vector(block_size)
    previous_encrypted_block = initialization_vector

    for block in msg_blocks: # Browsing the blocks
        decrypted_block = block
        for round_number in range(75, -1, -1):
        #for i in range(1):
            #round_number = 75

            # 1 - Reverse permute (same function here)
            decrypted_block = permute(decrypted_block)

            # 2 - Undo mixing
            decrypted_block = reverse_mix(decrypted_block)

            # 3 - Substracting the key if necessary (depending on the round number)
            if (round_number == 0) or ((round_number % 4) == 0) or (round_number == 75): # Need to substract the key here
                key_used_times += 1
                # Dividing the block into words
                block_words_list = divide_list(decrypted_block, len(decrypted_block)/64)
                decrypted_block_words = []
                for block_word in block_words_list: # Browsing the block words
                    #print("Used to DECRYPT : {0}".format(rounds_keywords_list[round_number][block_number]))
                    decrypted_block_words.append(xoring_two_lists(block_word, rounds_keywords_list[round_number][block_number]))
                decrypted_block = merge_list_of_lists(decrypted_block_words)

        # Xoring with the previous encrypted block
        decrypted_block = xoring_two_lists(decrypted_block, previous_encrypted_block)

        decrypted_msg_blocks.append(decrypted_block)
        block_number += 1
        previous_encrypted_block

    decrypted_msg = merge_list_of_lists(decrypted_msg_blocks)

    return decrypted_msg # Regular ECB decryption mode


def main():
    print("Select your encryption function")
    print("->1<- ThreeFish symetric encryption")
    print("->2<- Cramer-Shoup encryption")
    print("->3<- Hash a message")
    print("->4<- ThreeFish symetric decryption")
    print("->5<- Cramer-Shoup decryption")
    print("->6<- Verify a hash")

    choice = input("Choice : ")
    

    print("Select the input type")
    print("->1<- Text")
    print("->2<- File")
    subchoice = input("Choice : ")

    if choice == 1:
        # Block size
        block_size = input("Block size (256, 512 or 1024 bits) : ")

        # Key used
        key = raw_input("Key : ")
        key_hash = hashlib.md5() # Using md5 - most convenient output size for this purpose
        key_hash.update(key)
        key_bits = tobits(key_hash.hexdigest())

        # Checking the key size - must be EXACTLY equal to the block size
        if len(key_bits) < block_size:
            # Repeating the key bits until the list is as long as the block size
            i = 0
            while len(key_bits) < block_size:
                key_bits.append(key_bits[i])
                i+=1

        # Encryption mode : ECB or CBC
        print("Select the encryption mode")
        print("->1<- ECB")
        print("->2<- CBC")
        encmode = input("Choice : ")

        if subchoice == 1:
            # Text to encrypt
            text_to_encrypt = raw_input("Text to encrypt : ")
            bits_to_encrypt = tobits(text_to_encrypt)
            print("Text to encrypt size : {0} bits".format(len(bits_to_encrypt)))

            # Checking the input size
            if len(bits_to_encrypt) < block_size:
                print("The total number of bits ({0} bits) to encrypt is lower than the block size ({1} bits)".format(len(bits_to_encrypt), block_size))
                # Padding zeros, so we've got at least one block to encrypt
                while len(bits_to_encrypt) < block_size:
                    bits_to_encrypt.append(0)
                print("New nb_of_bits_to_encrypt : {0}".format(len(bits_to_encrypt)))

            # Now that the key size and the input size are ok, we may continue
            print("[1] - key_bits = {0} ; bits_to_encrypt = {1} ; block_size = {2}".format(len(key_bits), len(bits_to_encrypt), block_size))


            if encmode == 1:
                encrypted_msg = threefish_encrypt(key_bits, bits_to_encrypt, block_size)
            else:
                encrypted_msg = cbc_threefish_encrypt(key_bits, bits_to_encrypt, block_size)

            #decrypted_msg = threefish_decrypt(key_bits, encrypted_msg, block_size)

            enc_text = frombits(encrypted_msg)
            print("Clear message : {0}".format(bits_to_encrypt))
            print("Encrypted message : {0}".format(encrypted_msg))
            #print("Decrypted message : {0}".format(decrypted_msg))

            #dec_text = frombits(decrypted_msg)
            print("Clear text : {0}".format(text_to_encrypt))
            print("Encrypted text : {0}".format(enc_text))

            # Now writing the encrypted message (encrypted_msg) to a new file for easier retrieving
            filename_encrypted_text_output = "encrypted_text_"+repr(time.time())
            write_bits_to_file(filename_encrypted_text_output, encrypted_msg)
            print("Encryption written to {0}".format(filename_encrypted_text_output))


        elif subchoice == 2:
            # File to encrypt
            file_to_encrypt = raw_input("File path : ")
            clear_file_bits = open_file(file_to_encrypt, block_size)

            original_file_msg = frombits(clear_file_bits)

            # Checking the input size
            if len(clear_file_bits) < block_size:
                print("The total number of bits ({0} bits) to encrypt is lower than the block size ({1} bits)".format(len(clear_file_bits), block_size))
                # Padding zeros, so we've got at least one block to encrypt
                while len(clear_file_bits) < block_size:
                    clear_file_bits.append(0)
                print("New nb_of_bits_to_encrypt : {0}".format(len(clear_file_bits)))

            print("Number of bits to encrypt : {0}".format(len(clear_file_bits)))
            print("Encrypting... please wait")
            if encmode == 1:
                encrypted_file_bits = threefish_encrypt(key_bits, clear_file_bits, block_size)
            else:
                encrypted_file_bits = cbc_threefish_encrypt(key_bits, clear_file_bits, block_size)

            #print("Encrypted file bits : {0}".format(encrypted_file_bits))

            # Writing the encrypted bits to a new file for easier retrieving
            filename_encrypted_file_output = "encrypted_file_"+repr(time.time())
            write_bits_to_file(filename_encrypted_file_output, encrypted_file_bits)
            print("Encryption written to {0}".format(filename_encrypted_file_output))

            #print("Decrypting... please wait")
            #decrypted_file_bits = threefish_decrypt(key_bits, encrypted_file_bits, block_size)
            #decrypted_file_msg = frombits(decrypted_file_bits)

            print("Clear file bits length : {0}".format(len(clear_file_bits)))
            print("Encrypted file bits length : {0}".format(len(encrypted_file_bits)))
            #print("Decrypted file bits length : {0}".format(len(decrypted_file_bits)))


            #print("Decrypted file message : {0}".format(decrypted_file_msg))

            #if clear_file_bits == decrypted_file_bits:
            #if (clear_file_bits, decrypted_file_bits):
            #    print("Files are similar")
            #else:
            #    print("Files aren't similar :(")

    elif choice == 2:
        timestamp = gettimestamp()
       
        
        if subchoice == 1:
            text_to_encrypt = raw_input("Text to encrypt : ")
            
            key = keygen_cramershoup()
            filename = cypher_cramershoup(text_to_encrypt,key,timestamp)
            print("File saved to ",filename)
        
        elif subchoice == 2:
            file_to_encrypt = raw_input("File path : ")
            key = keygen(timestamp)
            filename = cypherfile_cramershoup(file_to_encrypt,key,timestamp)
            print("File saved to ",filename)
            
    elif choice == 3:
      
        if subchoice == 1:
            txt = raw_input("Text to hash : ")
            hashresult = hashtxt(txt)
            print("Hash : ",hashresult[0],", saved to ",hashresult[1])
            
        elif subchoice == 2:
            filepath = raw_input("File path : ")
            hashresult = hashfile(filepath)
            print("Hash : ",hashresult[0],", saved to ",hashresult[1])
            
        
        
    elif choice == 4:
        # Block size
        block_size = input("Block size (256, 512 or 1024 bits) : ")

        # Key used
        key = raw_input("Key : ")
        key_hash = hashlib.md5() # Using md5 - most convenient output size for this purpose
        key_hash.update(key)
        key_bits = tobits(key_hash.hexdigest())

        # Checking the key size - must be EXACTLY equal to the block size
        if len(key_bits) < block_size:
            # Repeating the key bits until the list is as long as the block size
            i = 0
            while len(key_bits) < block_size:
                key_bits.append(key_bits[i])
                i+=1

        # Encryption mode : ECB or CBC
        print("Select the encryption mode")
        print("->1<- ECB")
        print("->2<- CBC")
        encmode = input("Choice : ")

        if subchoice == 1:
            encrypted_msg = input("Encrypted list : ")
            if encmode == 1:
                decrypted_msg = threefish_decrypt(key_bits, encrypted_msg, block_size)
            else:
                decrypted_msg = cbc_threefish_decrypt(key_bits, encrypted_msg, block_size)

            decrypted_txt = frombits(decrypted_msg)

            print("Decrypted message bits : {0}".format(decrypted_msg))
            print("Decrypted text : {0}".format(decrypted_txt))
        elif subchoice == 2:
            encrypted_filename = raw_input("File path : ")
            encrypted_msg = read_file_content(encrypted_filename)
            print("Number of bits to decrypt : {0}".format(len(encrypted_msg)))
            print("Decrypting... please wait")
            if encmode == 1:
                decrypted_msg = threefish_decrypt(key_bits, encrypted_msg, block_size)
            else:
                decrypted_msg = cbc_threefish_decrypt(key_bits, encrypted_msg, block_size)

            print("Number of bits decrypted : {0}".format(len(decrypted_msg)))
            decrypted_txt = frombits(decrypted_msg)

            print("Decrypted text : {0}".format(decrypted_txt))

            write_text_to_file(encrypted_filename+"_decrypted", decrypted_txt)

            print("Decrypted text written to {0}_decrypted".format(encrypted_filename))
    elif choice == 5:
        
        filepath = raw_input("File path : ")
        msgdecyphered = decypher_cramershoup(filepath)
        print("Deciphered message : ",msgdecyphered)
        
    elif choice == 6:
        if subchoice == 1:
            msgtocheck = raw_input("Message to check : ")
            file_path = raw_input("Hash file to check : ")
            boolhash = verifhash_txt(msgtocheck,file_path)
            if boolhash:
                print("The two hashs are equal ! ")
            else:
                print("The two hashs are not equal ! ")
        elif subchoice == 2:
            filetocheck = raw_input("File to check : ")
            filehashtocheck = raw_input("Hash file to check : ")
            boolhash = verifhash_file(filetocheck,filehashtocheck)
            if boolhash:
                print("The two hashs are equal ! ")
            else:
                print("The two hashs are not equal ! ")            
            
def getscriptpath():
    pathfile = os.path.realpath(__file__)
    filename = "\\" + pathfile.split("\\").pop()
    filepath = pathfile.replace(filename,"")
    
    return filepath

if __name__ == "__main__":
    main()
    
    
   
