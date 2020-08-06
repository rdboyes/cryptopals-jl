# Set 3!

strings = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]

random_key = UInt8[rand(1:255) for n in 1:16]

using Base64
using Nettle

enc = Encryptor("AES128", random_key)
dec = Decryptor("AES128", random_key)

function pad(bytes)
    pad_length = 16 - mod(length(bytes), 16)
    for i in 1:pad_length
        append!(bytes, pad_length)
    end
    return bytes
end

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


function encrypt_string()
    IV = UInt8[rand(1:255) for n in 1:16]
    bytes = pad(base64decode(strings[rand(1:10)]))
    return cbc_encrypt(bytes, IV), IV
end

encrypt_string()

check_valid_padding(ciphertext, IV)
    
