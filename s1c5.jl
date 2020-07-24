# Challenge 5
# Encryption using repeating key xor

stanza = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"

# convert stanza to bytes

function ascii_to_bytes(text)
    bytes = UInt8[]

    for i in 1:length(text)
        append!(bytes, Int(text[i]))
    end

    return bytes
end

input = ascii_to_bytes(stanza)

@assert String(input) == stanza

key = ascii_to_bytes("ICE")

function repeating_key_encrypt(bytes, key)
    ciphertext = UInt8[]
    for i in 1:length(bytes)
        append!(ciphertext, xor(bytes[i], key[1 + mod(i - 1, length(key))]))
    end
    return ciphertext
end

target = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

@assert bytes2hex(repeating_key_encrypt(input, key)) == target 
