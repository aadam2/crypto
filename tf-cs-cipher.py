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

# Functions definitions
# def threefish_encrypt()

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

        # Now that the


if __name__ == "__main__":
    main()
