# Set 2 Challenge 11
# CBC ECB Oracle

# need to force repeat blocks in ecb to be able to detect
# 5 - 10 bytes appended before and after
# input needs to fill block 1 (11 bytes), then take up two full blocks (32)
# so we make the input 43 copies of a single byte

input = [0x70 for i in 1:43]

using Nettle

function cbc_encrypt(bytes, IV, key)
    enc = Encryptor("AES128", key)

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

function pad(bytes)
    pad_length = 16 - mod(length(bytes), 16)
    for i in 1:pad_length
        append!(bytes, pad_length)
    end
    return bytes
end

function random_encrypt(input)
    choice = rand(1:2)

    key = UInt8[rand(1:255) for i in 1:16]

    before_bytes_count = rand(5:10)
    after_bytes_count = rand(5:10)

    to_encrypt = UInt8[rand(1:255) for i in 1:before_bytes_count]
    append!(to_encrypt, input)
    append!(to_encrypt, UInt8[rand(1:255) for i in 1:after_bytes_count])

    to_encrypt = pad(to_encrypt)

    if choice == 1
        enc = Encryptor("AES128", key)
        return encrypt(enc, to_encrypt)
    end
    if choice == 2
        return cbc_encrypt(to_encrypt, UInt8[rand(1:255) for i in 1:16], key)
    end
end

function oracle(ciphertext)
    if ciphertext[17:32] == ciphertext[33:48]
        return "ECB"
    else
        return "CBC"
    end
end

oracle(random_encrypt(input))
