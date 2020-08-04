# last challenge of set 2
# CBC bitflipping

random_key = UInt8[rand(1:255) for n in 1:16]

function pad(bytes)
    pad_length = 16 - mod(length(bytes), 16)
    for i in 1:pad_length
        append!(bytes, pad_length)
    end
    return bytes
end

IV = [0x00 for n in 1:16]

using Nettle

# cbc encryption:
# XOR previous ciphertext and current block of plaintext
# ECB encrypt this new next, it becomes the ciphertext

enc = Encryptor("AES128", random_key)
dec = Decryptor("AES128", random_key)

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

function addstrings(userdata, IV = IV)
    userdata = replace(userdata, ";"=>"")
    userdata = replace(userdata, "="=>"")
    to_encrypt = string("comment1=cooking%20MCs;userdata=",
                    userdata,
                    ";comment2=%20like%20a%20pound%20of%20bacon")
    return cbc_encrypt(pad(ascii_to_bytes(to_encrypt)), IV)
end

function is_admin(bytes, IV)
    text = String(cbc_decrypt(bytes, IV))
    return occursin(";admin=true;", text)
end

addstrings("admin=true", IV)

# comment1=cooking |
# %20MCs;userdata= |
# aaaaalaaaaalaaaa | scramble this block
# filla;admin=true |
# ;comment2=%20lik |
# e%20a%20pound%20 |
# of%20bacon666666 |

# semi colon is 0011 1011
# colon is      0011 1010

# equals is     0011 1101
# < is          0011 1100

ciphertext = addstrings("aaaaalaaaaalaaaafilla:admin<true")

# change the last bit of the matching locations

ciphertext[38] = ciphertext[38] + 1
ciphertext[44] = ciphertext[44] - 1

is_admin(ciphertext, IV) # true
