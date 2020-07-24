# Set 1 Challenge 3
# Single Byte XOR Cipher

str = hex2bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

keys = UInt8[]

for i in 1:255
    append!(keys, i)
end

function single_char_xor(hex_string, char)
    out = UInt8[]

    for i in 1:length(hex_string)
        append!(out, xor(char, hex_string[i]))
    end

    return out
end

out = Array{UInt8, 2}(undef, 255, 34)

function score_text(bytes)
    score = 0
    for i in 1:length(bytes)
        if bytes[i] == 0x61; score += 1; end # a
        if bytes[i] == 0x65; score += 1; end # e
        if bytes[i] == 0x69; score += 1; end # i
        if bytes[i] == 0x6f; score += 1; end # o
        if bytes[i] == 0x75; score += 1; end # u
    end
    return score
end

out = Array{UInt8, 2}(undef, 255, 34)
scores = UInt16[]

for i in 1:255
    temp = single_char_xor(str, keys[i])
    append!(scores, score_text(temp))
    for j in 1:34
        out[i, j] = temp[j]
    end
end

String(out[findmax(scores)[2], :])
