# Set 1 Challenge 6
# It's on now

using Base64

str1 = "this is a test"
str2 = "wokka wokka!!!"

function ascii_to_bytes(text)
    bytes = UInt8[]

    for i in 1:length(text)
        append!(bytes, Int(text[i]))
    end

    return bytes
end

function hamming_distance(bytes1, bytes2)
    dist = 0

    for i in 1:length(bytes1)
        bits1 = bitstring(bytes1[i])
        bits2 = bitstring(bytes2[i])
        for j in 1:8
            if bits1[j] != bits2[j]
                dist += 1
            end
        end
    end

    return dist
end

@assert hamming_distance(ascii_to_bytes(str1), ascii_to_bytes(str2)) == 37

key_size = 2:40

# read the file

file_in = readlines("D:\\Projects\\cryptopals-jl\\data\\6.txt")

bytes_in = UInt8[]

for i in 1:length(file_in)
    append!(bytes_in, base64decode(file_in[i]))
end

distances = [Inf]

for key_size in 2:40
    first_block = bytes_in[1:key_size]
    second_block = bytes_in[(key_size + 1):(key_size * 2)]
    third_block = bytes_in[(2 * key_size + 1):(key_size * 3)]
    fourth_block = bytes_in[(3 * key_size + 1):(key_size * 4)]

    total = hamming_distance(first_block, second_block) +
    hamming_distance(first_block, third_block) +
    hamming_distance(first_block, fourth_block) +
    hamming_distance(second_block, third_block) +
    hamming_distance(second_block, fourth_block) +
    hamming_distance(third_block, fourth_block)

    append!(distances, total/key_size)
end

blocks = Array{UInt8, 2}(undef, 29, 99)

for j in 1:99
    for i in 1:29
        blocks[i, j] = bytes_in[1 + (j - 1) * 29 + (i - 1)]
    end
end


function single_char_xor(hex_string, char)
    out = UInt8[]

    for i in 1:length(hex_string)
        append!(out, xor(char, hex_string[i]))
    end

    return out
end

function score_text(bytes)
    score = 0
    for i in 1:length(bytes)
        if bytes[i] > 0x61 && bytes[i] < 0x7a
            score += 1
        end
        if bytes[i] > 0x41 && bytes[i] < 0x5a
            score += 1
        end
        if bytes[i] == 0x20
            score += 2
        end
        if bytes[i] < 0x20
            score = score - 10
        end
    end
    return score
end

function decrypt_single_char_xor(bytes)
    keys = UInt8[]

    for i in 1:255
        append!(keys, i)
    end

    out = Array{UInt8, 2}(undef, 255, length(bytes))
    scores = Int16[]

    for i in 1:255
        temp = single_char_xor(bytes, keys[i])
        append!(scores, score_text(temp))
        for j in 1:length(temp)
            out[i, j] = temp[j]
        end
    end

    return keys[findmax(scores)[2], :]
end

key_bytes = UInt8[]

for i in 1:29
    append!(key_bytes, decrypt_single_char_xor(blocks[i, :]))
end

function repeating_key_decrypt(bytes, key)
    plaintext = UInt8[]
    for i in 1:length(bytes)
        append!(plaintext, xor(bytes[i], key[1 + mod(i - 1, length(key))]))
    end
    return plaintext
end

bytes_decrypted = repeating_key_decrypt(bytes_in, key_bytes)

println(String(bytes_decrypted))
