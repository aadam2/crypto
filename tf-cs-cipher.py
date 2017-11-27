# Generic functions
def tobits(s): # Converts characters into a list of bits
    result = []
    for c in s:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        result.extend([int(b) for b in bits])
    return result

def frombits(bits): # Converts a list of bits into caracters
    chars = []
    for b in range(len(bits) / 8):
        byte = bits[b*8:(b+1)*8]
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
    return ''.join(chars)

def divide_list(bits_list, num): # Used to generate equal size subkeys
    avg = len(bits_list) / float(num)
    out = []
    last = 0.0

    while last < len(bits_list):
        out.append(bits_list[int(last):int(last + avg)])
        last += avg

    return out

def xoring_two_lists(list_A, list_B):
    xored_list = []
    list_size = len(list_A)
    for i in range(list_size):
        xored_list.append(list_A[i] ^ list_B[i])
    return xored_list

def xoring_list_of_lists(subkeys_list):
    nb_lists = len(subkeys_list)
    last_subkey = subkeys_list[0]
    for i in range(1, nb_lists):
        last_subkey = xoring_two_lists(last_subkey,subkeys_list[1])
    print("Last subkey (without C yet) : {0}".format(last_subkey))

    C = [0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0]
    last_subkey = xoring_two_lists(last_subkey, C)
    print("Last subkey (AFTER C XOR) : {0}".format(last_subkey))
    return last_subkey

# Functions definitions

# ThreeFish related
def threefish_key_schedule(key, block_size):
    nb_key_words = block_size / 64
    print("Number of key words : {0}".format(nb_key_words))
    keywords_list = divide_list(key, nb_key_words)
    print("Keywords list : {0}".format(keywords_list))

    # Now adding kN : kN = k0 ^ k1 ^ ... ^ k_N-1 ^ C
    last_subkey = xoring_list_of_lists(keywords_list)
    print("Received last subkey : {0}".format(last_subkey))

    # Appending the last subkey to the key
    keywords_list.append(last_subkey)
    print("(Almost) Complete key words list : {0}".format(keywords_list))
    print("(Almost) Complete key words list size : {0}".format(len(keywords_list)))
    return


def threefish_encrypt(key, msg_bits, block_size):
    key_words = threefish_key_schedule(key, block_size) # Generating the key words
    return


# Calling user defined functions
def main():
    print("Select your encryption function")
    print("->1<- ThreeFish symetric encryption")
    print("->2<- Cramer-Shoup encryption")
    print("->3<- Hash a message")
    print("->4<- ThreeFish symetric decryption")
    print("->5<- Cramer-Shoup decryption")
    print("->6<- Verify a hash")

    choice = input("Choice : ")
    if choice == 1:
        # Block size
        block_size = input("Block size (256, 512 or 1024 bits) : ")

        # Text to encrypt
        # ----------------------------------------------------------------------
        text_to_encrypt = raw_input("Text to encrypt : ")
        bits_to_encrypt = tobits(text_to_encrypt)
        print("Bits to encrypt : {0}".format(bits_to_encrypt))
        print("Text to encrypt size : {0} bits".format(len(bits_to_encrypt)))
        # ----------------------------------------------------------------------

        # Key used
        # ----------------------------------------------------------------------
        key = raw_input("Key : ")
        key_bits = tobits(key)
        print("Key bits : {0}".format(key_bits))
        print("Key size : {0}".format(len(key_bits)))
        # ----------------------------------------------------------------------

        # Checking the input size
        # ----------------------------------------------------------------------
        if len(bits_to_encrypt) < block_size:
            print("The total number of bits ({0} bits) to encrypt is lower than the block size ({1} bits)".format(len(bits_to_encrypt), block_size))
            # Padding zeros, so we've got at least one block to encrypt
            while len(bits_to_encrypt) < block_size:
                bits_to_encrypt.append(0)
            print("New bits_to_encrypt : {0}".format(bits_to_encrypt))
            print("New nb_of_bits_to_encrypt : {0}".format(len(bits_to_encrypt)))
        # ----------------------------------------------------------------------

        # Checking the key size - must be EXACTLY equal to the block size
        # ----------------------------------------------------------------------
        if len(key_bits) < block_size:
            print("The key size ({0} bits) is lower than the block size ({1} bits)".format(len(key_bits), block_size))
            # Repeating the key bits until the list is as long as the block size
            i = 0
            while len(key_bits) < block_size:
                key_bits.append(key_bits[i])
                i+=1
            print("New key : {0}".format(key_bits))
            print("New key size : {0}".format(len(key_bits)))
        elif len(key_bits) > block_size:
            print("The key size ({0} bits) is greater than the block size ({1} bits)".format(len(key_bits), block_size))
            nb_of_bits_to_remove = len(key_bits) - block_size
            key_bits = key_bits[:len(key_bits)-nb_of_bits_to_remove]
            print("Shortened key : {0}".format(key_bits))
            print("Shortened key size : {0}".format(len(key_bits)))
        else:
            print("Wow, an exactly {0} bit long key, I'm impressed".format(len(key_bits)))
        # ----------------------------------------------------------------------

        # Now that the key size and the input size are OK, we may continue
        threefish_encrypt(key_bits, bits_to_encrypt, block_size)

if __name__ == "__main__":
    main()
