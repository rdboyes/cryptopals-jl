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

prepend_bytes = UInt8[rand(1:255) for n in 1:rand(1:100)]

text_to_decrypt = base64decode(
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK")

function breakable_encryption_pre(input_bytes)
    return encrypt(enc, pad([prepend_bytes; input_bytes; text_to_decrypt]))
end

function breakable_encryption(input_bytes)
    return encrypt(enc, pad([input_bytes; text_to_decrypt]))
end

# find the block size that "breakable_encryption" is using

function discover_block_size()
    block_size = -1
    for i in 2:32
        test_block = UInt8[0x60 for n in 1:(i*3)]
        ciphertext = breakable_encryption_pre(test_block)
        num_blocks = (length(ciphertext) ÷ i) - 2
        for j in 1:num_blocks
            o = (j-1) * i
            if (ciphertext[o + 1:o + i] == ciphertext[(o + i + 1):(o + 2 * i)])
                block_size = i
                return block_size
            end
        end
    end
    return block_size
end

discover_block_size() # 16

# detect that the program is using ecb

function oracle(ciphertext, key_length)
    test_block = UInt8[0x60 for n in 1:(key_length*3)]
    num_blocks = (length(ciphertext) ÷ key_length) - 2
    for j in 1:num_blocks
        o = (j-1) * key_length
        if (ciphertext[o + 1:o + key_length] == ciphertext[(o + key_length + 1):(o + 2 * key_length)])
            return "ECB"
        end
    end
    return "CBC"
end

oracle(breakable_encryption_pre(UInt8[0x00 for n in 1:48]), 16)

# returns "ECB"

# vs. solution to 12, we need a function that can strip off the prepended bytes

function count_prepended_bytes()
    key_length = 16
    for i in 32:48
        test_block = UInt8[0x60 for n in 1:i]
        ciphertext = breakable_encryption(test_block)
        num_blocks = (length(ciphertext) ÷ key_length) - 2
        for j in 1:num_blocks
            o = (j-1) * key_length
            if (ciphertext[o + 1:o + key_length] == ciphertext[(o + key_length + 1):(o + 2 * key_length)])
                return (j-2) * key_length + (48 - i)
            end
        end
    end
end

count_prepended_bytes()

function be_no_prepend(input_bytes)
    fill_block = UInt8[0x00 for n in 1:6]
    be = breakable_encryption_pre([fill_block; input_bytes])
    return be[97:length(be)]
end

# Check that the new function produces the same ciphertext as the old one
# would have if the bytes were not prepended

message = UInt8[0x00 for n in 1:16]

@assert be_no_prepend(message) == breakable_encryption(message)

# decode the message again

decoded_secret = UInt8[]

secret_message_blocks = length(be_no_prepend(UInt8[])) ÷ 16

for block = 1:secret_message_blocks
    crafted_input = [UInt8[0x60 for n in 1:15]; decoded_secret]
    for within_block_pos = 1:16
        target = UInt8[0x60 for n in 1:(16 - within_block_pos)]

        target_output = be_no_prepend(target)

        for i in 0x00:0xff
            attempt = be_no_prepend([crafted_input; i])
            offset = (block - 1) * 16
            if attempt[(offset + 1):(offset + 16)] == target_output[(offset + 1):(offset + 16)]
                append!(decoded_secret, i)
            end
        end

        popfirst!(crafted_input)
        append!(crafted_input, last(decoded_secret))
    end
end

print(String(decoded_secret))
