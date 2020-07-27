# Breaking penguins

using Base64
using Nettle

random_key = UInt8[rand(0x00:0xff) for n in 1:16]
enc = Encryptor("AES128", random_key)

function pad(bytes)
    pad_length = 16 - mod(length(bytes), 16)
    for i in 1:pad_length
        append!(bytes, pad_length)
    end
    return bytes
end

text_to_decrypt = base64decode(
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK")

function breakable_encryption(input_bytes)
    append!(input_bytes, text_to_decrypt)
    return encrypt(enc, pad(input_bytes))
end

# find the block size that "breakable_encryption" is using

for i in 1:32
    test_block = UInt8[0x60 for n in 1:(i*2)]
    ciphertext = breakable_encryption(test_block)
    if (ciphertext[1:i] == ciphertext[(i+1):(2*i)])
        println(i)
        break
    end
end

# prints 16

# detect that the program is using ecb

function oracle(ciphertext)
    if ciphertext[1:16] == ciphertext[17:32]
        return "ECB"
    else
        return "CBC"
    end
end

oracle(breakable_encryption(UInt8[0x00 for n in 1:32]))

# returns "ECB"



crafted_input = UInt8[0x60 for n in 1:15]

target_output = breakable_encryption(crafted_input)

decoded_secret = UInt8[]

for i in 1:255
    attempt = breakable_encryption(vcat(crafted_input, i))
    if attempt[1:16] == target_output[1:16]
        append!(decoded_secret, i)
    end
end
