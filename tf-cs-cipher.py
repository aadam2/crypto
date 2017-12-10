from bitstring import BitArray

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

def merge_list_of_lists(l):
    flat_list = [item for sublist in l for item in sublist]
    return flat_list

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

    if len(mod_sum_list) > len(list_A): # Removing the last element if necessary
        mod_sum_list.pop(0)

    mod_sum_list = [int(x) for x in mod_sum_list] # Converting list elements to int

    while len(mod_sum_list) < 64:
        mod_sum_list.insert(0, 0)

    return mod_sum_list

def binary_sub(list_A, list_B): # Computes binary substraction ; list_A shall be greater than list_B
    print("Substracting {0} from {1}".format(list_B, list_A))
    a = BitArray(list_A)
    b = BitArray(list_B)
    bin_sub = bin(int(a.bin, 2) - int(b.bin, 2))
    print("bin_sub : {0}".format(bin_sub))
    bin_sub = bin_sub[2:] # [2:] to chop off the "0b" part
    print("Chopped off bin_sub : {0}".format(bin_sub))

    if (bin_sub[0] != 0) or (bin_sub[0] != 1):
        bin_sub = bin_sub[1:] # To remove the potential b remaining

    print("Cleaned bin_sub : {0}".format(bin_sub))

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
    print("Number of key words : {0}".format(nb_key_words))
    keywords_list = divide_list(key, nb_key_words)

    # Now adding kN : kN = k0 ^ k1 ^ ... ^ k_N-1 ^ C
    last_subkey = xoring_list_of_lists(keywords_list)

    # Appending the last subkey to the key
    keywords_list.append(last_subkey)

    round_list = []
    rounds_keywords_list = [] # List of lists of lists, keywords list for each round (Round -> Keywords_List -> Keyword)

    N = nb_key_words
    print("[2] - N = {0}".format(N))
    print("[3] - keywords_list length = {0}".format(len(keywords_list)))
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

    nb_msg_blocks = len(msg_bits) / block_size
    msg_blocks = divide_list(msg_bits, nb_msg_blocks)

    round_number = 0
    block_number = 0
    key_used_times = 0

    encrypted_msg_blocks = [] # May contain 1 or several blocks

    for block in msg_blocks: # Browsing the blocks
        encrypted_block = block
        for round_number in range(76): # Browsing the rounds

            # 1 - Adding the key if necessary
            if (round_number == 0) or ((round_number % 4) == 0) or (round_number == 75): # Need to add key here
                key_used_times += 1
                # Dividing the block into words
                block_words_list = divide_list(encrypted_block, len(encrypted_block)/64)
                encrypted_block_words = []
                for block_word in block_words_list: # Browsing block words
                    encrypted_block_words.append(modular_addition(block_word, rounds_keywords_list[round_number][block_number]))
                encrypted_block = merge_list_of_lists(encrypted_block_words)

            # 2 - Mixing (Substitute)
            encrypted_block = mix(encrypted_block)

            # 3 - Permute
            encrypted_block = permute(encrypted_block)

        encrypted_msg_blocks.append(encrypted_block)
        block_number += 1

    encrypted_msg = merge_list_of_lists(encrypted_msg_blocks)

    return encrypted_msg

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

            # 1 - Substracting the key if necessary (depending on the round number)
            if (round_number == 0) or ((round_number % 4) == 0) or (round_number == 75): # Need to substract the key here
                key_used_times += 1
                # Dividing the block into words
                block_words_list = divide_list(decrypted_block, len(decrypted_block)/64)
                decrypted_block_words = []
                for block_word in block_words_list: # Browsing the block words
                    decrypted_block_words.append(binary_sub(block_word, rounds_keywords_list[round_number][block_number]))
                decrypted_block = merge_list_of_lists(decrypted_block_words)

            # 2 - Reverse permute (same function here)
            decrypted_block = permute(decrypted_block)

            # 3 - Undo mixing
            decrypted_block = reverse_mix(decrypted_block)

        decrypted_msg_blocks.append(decrypted_block)
        block_number += 1

    decrypted_msg = merge_list_of_lists(decrypted_msg_blocks)

    return decrypted_msg

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
        text_to_encrypt = raw_input("Text to encrypt : ")
        bits_to_encrypt = tobits(text_to_encrypt)
        print("Text to encrypt size : {0} bits".format(len(bits_to_encrypt)))

        # Key used
        key = raw_input("Key : ")
        key_bits = tobits(key)
        print("Key size : {0}".format(len(key_bits)))

        # Checking the input size
        if len(bits_to_encrypt) < block_size:
            print("The total number of bits ({0} bits) to encrypt is lower than the block size ({1} bits)".format(len(bits_to_encrypt), block_size))
            # Padding zeros, so we've got at least one block to encrypt
            while len(bits_to_encrypt) < block_size:
                bits_to_encrypt.append(0)
            print("New nb_of_bits_to_encrypt : {0}".format(len(bits_to_encrypt)))

        # Checking the key size - must be EXACTLY equal to the block size
        if len(key_bits) < block_size:
            print("The key size ({0} bits) is lower than the block size ({1} bits)".format(len(key_bits), block_size))
            # Repeating the key bits until the list is as long as the block size
            i = 0
            while len(key_bits) < block_size:
                key_bits.append(key_bits[i])
                i+=1
            print("New key size : {0}".format(len(key_bits)))
        elif len(key_bits) > block_size:
            print("The key size ({0} bits) is greater than the block size ({1} bits)".format(len(key_bits), block_size))
            nb_of_bits_to_remove = len(key_bits) - block_size
            key_bits = key_bits[:len(key_bits)-nb_of_bits_to_remove]
            print("Shortened key size : {0}".format(len(key_bits)))
        else:
            print("Wow, an exactly {0} bit long key, I'm impressed".format(len(key_bits)))

        # Now that the key size and the input size are OK, we may continue
        print("[1] - key_bits = {0} ; bits_to_encrypt = {1} ; block_size = {2}".format(len(key_bits), len(bits_to_encrypt), block_size))
        encrypted_msg = threefish_encrypt(key_bits, bits_to_encrypt, block_size)

        decrypted_msg = threefish_decrypt(key_bits, encrypted_msg, block_size)

        print("Clear message : {0}".format(bits_to_encrypt))
        print("Encrypted message : {0}".format(encrypted_msg))
        print("Decrypted message : {0}".format(decrypted_msg))


if __name__ == "__main__":
    main()
