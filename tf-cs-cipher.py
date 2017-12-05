# Generic functions
################################################################################

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
    #print("[2] - XORing {0} and {1}".format(list_A, list_B))
    xored_list = []
    list_size = len(list_A)
    for i in range(list_size):
        xored_list.append(list_A[i] ^ list_B[i])
    #print("[3] - XOR result : {0}".format(xored_list))
    #print("####################################################################")
    return xored_list

def xoring_list_of_lists(subkeys_list):
    nb_lists = len(subkeys_list)
    last_subkey = subkeys_list[0]
    for i in range(1, nb_lists):
        print("Having i = {0}".format(i))
        last_subkey = xoring_two_lists(last_subkey,subkeys_list[i])
    #print("Last subkey (without C yet) : {0}".format(last_subkey))

    C = [0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0]
    last_subkey = xoring_two_lists(last_subkey, C)
    #print("Last subkey (AFTER C XOR) : {0}".format(last_subkey))
    return last_subkey

################################################################################

# Functions definitions
################################################################################
# ThreeFish related
def threefish_key_schedule(key, block_size): # Generates the original keywords list (used for the first round)

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
    print("Number of key words : {0}".format(nb_key_words))
    keywords_list = divide_list(key, nb_key_words)

    # Now adding kN : kN = k0 ^ k1 ^ ... ^ k_N-1 ^ C
    last_subkey = xoring_list_of_lists(keywords_list)

    # Appending the last subkey to the key
    keywords_list.append(last_subkey)

    # keywords_list now contains the original keywords list (used for the first round)
    round_list = []
    rounds_keywords_list = [] # List of lists of lists, keywords list for each round (Round->Keywords_List->Keyword)
    # Doing the first round

    N = nb_key_words
    print("[2] - N = {0}".format(N))
    print("[3] - keywords_list length = {0}".format(len(keywords_list)))
    for i in range(20): # Browsing the rounds
        for n in range(N-3): # Browsing the blocks
            current_index = (n + i) % (N + 1)
            print ("With i = {0} and n = {1}, we have current_index = {2}".format(i, n, current_index))
            #round_list[n] = keywords_list[(n + i) % (N + 1)]
            round_list.append(keywords_list[(n + i) % (N + 1)])
        print("[4] - round_list so far : {0}".format(round_list))
        # round_list[N-3] = xoring_two_lists(keywords_list[(N - 3 + i) % (N + 1)], tweaks[(i % 3)])
        round_list.append(xoring_two_lists(keywords_list[(N - 3 + i) % (N + 1)], tweaks[(i % 3)])) # N-3
        #round_list[N-2] = xoring_two_lists(keywords_list[(N - 2 + i) % (N + 1)], tweaks[((i + 1) % 3)])
        round_list.append(xoring_two_lists(keywords_list[(N - 2 + i) % (N + 1)], tweaks[((i + 1) % 3)])) # N-2
        #round_list[N-1] = keywords_list[(N - 1 + i) % (N + 1)] # TODO Do the correction modular addition here (with i)
        round_list.append(keywords_list[(N - 1 + i) % (N + 1)]) # TODO Do the correction modular addition here (with i). Anyway, N-1 here
        rounds_keywords_list.append(round_list)

    return rounds_keywords_list

def threefish_encrypt(key, msg_bits, block_size):
    rounds_keywords_list = threefish_key_schedule(key, block_size) # Generating the key words
    print("Keywords list for the different rounds : ")
    print(rounds_keywords_list)


    print("rounds_keywords_list[0] : {0}".format(rounds_keywords_list[0])) # Keywords for round 1
    print("len(rounds_keywords_list) : {0}".format(len(rounds_keywords_list)))
    print("len(rounds_keywords_list[0]) : {0}".format(len(rounds_keywords_list[0])))

    return

# Main function
################################################################################
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
        #print("Bits to encrypt : {0}".format(bits_to_encrypt))
        print("Text to encrypt size : {0} bits".format(len(bits_to_encrypt)))
        # ----------------------------------------------------------------------

        # Key used
        # ----------------------------------------------------------------------
        key = raw_input("Key : ")
        key_bits = tobits(key)
        #print("Key bits : {0}".format(key_bits))
        print("Key size : {0}".format(len(key_bits)))
        # ----------------------------------------------------------------------

        # Checking the input size
        # ----------------------------------------------------------------------
        if len(bits_to_encrypt) < block_size:
            print("The total number of bits ({0} bits) to encrypt is lower than the block size ({1} bits)".format(len(bits_to_encrypt), block_size))
            # Padding zeros, so we've got at least one block to encrypt
            while len(bits_to_encrypt) < block_size:
                bits_to_encrypt.append(0)
            #print("New bits_to_encrypt : {0}".format(bits_to_encrypt))
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
            #print("New key : {0}".format(key_bits))
            print("New key size : {0}".format(len(key_bits)))
        elif len(key_bits) > block_size:
            print("The key size ({0} bits) is greater than the block size ({1} bits)".format(len(key_bits), block_size))
            nb_of_bits_to_remove = len(key_bits) - block_size
            key_bits = key_bits[:len(key_bits)-nb_of_bits_to_remove]
            #print("Shortened key : {0}".format(key_bits))
            print("Shortened key size : {0}".format(len(key_bits)))
        else:
            print("Wow, an exactly {0} bit long key, I'm impressed".format(len(key_bits)))
        # ----------------------------------------------------------------------

        # Now that the key size and the input size are OK, we may continue
        print("[1] - key_bits = {0} ; bits_to_encrypt = {1} ; block_size = {2}".format(len(key_bits), len(bits_to_encrypt), block_size))
        #print("Key bits used : {0}".format(key_bits))
        threefish_encrypt(key_bits, bits_to_encrypt, block_size)

if __name__ == "__main__":
    main()
################################################################################
