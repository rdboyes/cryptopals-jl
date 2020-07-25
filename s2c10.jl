# set 2 challenge 10

# cbc mode implementation

IV = [0x00 for n in 1:16]

# cbc encryption:
# XOR previous ciphertext and current block of plaintext
# ECB encrypt this new next, it becomes the ciphertext

# cbc decryption
# starting from end, decrypt block with ECB
# then XOR with next ciphertext 
