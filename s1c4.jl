# Set 1 Challenge 4
# Detecting Single-Char XOR Ciphers

# Useful Functions from last Challenge

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

# Wrap the whole last challenge in a function

function decrypt_single_char_xor(hex)
    str = hex2bytes(hex)

    keys = UInt8[]

    for i in 1:255
        append!(keys, i)
    end

    out = Array{UInt8, 2}(undef, 255, length(str))
    scores = Int16[]

    for i in 1:255
        temp = single_char_xor(str, keys[i])
        append!(scores, score_text(temp))
        for j in 1:length(temp)
            out[i, j] = temp[j]
        end
    end

    return out[findmax(scores)[2], :]
end

# read file

file_in = readlines("D:\\Projects\\cryptopals-jl\\data\\4.txt")

# get the most english of all of these

all_attempts = Array{UInt8, 2}(undef, length(file_in), length(file_in[1]) ÷ 2)
final_scores = Int16[]

for i in 1:length(file_in)
    temp2 = decrypt_single_char_xor(file_in[i])
    append!(final_scores, score_text(temp2))
    for j in 1:length(temp2)
        all_attempts[i, j] = temp2[j]
    end
end

String(all_attempts[findmax(final_scores)[2], :])
