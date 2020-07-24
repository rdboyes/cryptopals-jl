# Set 1 Challenge 2
# Fixed XOR

str1 = hex2bytes("1c0111001f010100061a024b53535009181c")
str2 = hex2bytes("686974207468652062756c6c277320657965")

goal = "746865206b696420646f6e277420706c6179"

out = UInt8[]

for i in 1:length(str1)
    append!(out, xor(str1[i], str2[i]))
end

@assert bytes2hex(out) == goal
