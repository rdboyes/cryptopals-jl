# set 2 challenge 10

# cbc mode implementation

IV = [0x00 for n in 1:16]

using Nettle

# cbc encryption:
# XOR previous ciphertext and current block of plaintext
# ECB encrypt this new next, it becomes the ciphertext

test = "here's some texthere's some texthere's some texthere's some text"

enc = Encryptor("AES128", "YELLOW SUBMARINE")
dec = Decryptor("AES128", "YELLOW SUBMARINE")

@assert test == String(decrypt(dec, encrypt(enc, test)))

function ascii_to_bytes(text)
    bytes = UInt8[]

    for i in 1:length(text)
        append!(bytes, Int(text[i]))
    end

    return bytes
end

function cbc_encrypt(bytes, IV)
    blocks = []
    num_blocks = length(bytes) ÷ 16
    for i in 1:num_blocks
        push!(blocks, bytes[(1 + (i - 1) * 16):(16 + (i - 1) * 16)])
    end

    ciphertext = UInt8[]
    temp = encrypt(enc, IV .⊻ blocks[1])
    append!(ciphertext, temp)

    for i in 2:num_blocks
        temp = encrypt(enc, temp .⊻ blocks[i])
        append!(ciphertext, temp)
    end

    return ciphertext
end

# cbc decryption

function cbc_decrypt(bytes, IV)
    blocks = []
    num_blocks = length(bytes) ÷ 16
    for i in 1:num_blocks
        push!(blocks, bytes[(1 + (i - 1) * 16):(16 + (i - 1) * 16)])
    end

    plaintext = UInt8[]
    temp = IV .⊻ decrypt(dec, blocks[1])
    append!(plaintext, temp)
    last = temp

    for i in 2:num_blocks
        temp = blocks[i-1] .⊻ decrypt(dec, blocks[i])
        append!(plaintext, temp)
        last = temp
    end

    return plaintext
end

@assert String(cbc_decrypt(cbc_encrypt(ascii_to_bytes(test), IV), IV)) == test

# decrypt file

file_in = readlines("/Users/Randy/Documents/Github/cryptopals-jl/data/10.txt")

using Base64

bytes = UInt8[]

for i in 1:length(file_in)
    append!(bytes, base64decode(file_in[i]))
end

println(String(cbc_decrypt(bytes, IV)))
