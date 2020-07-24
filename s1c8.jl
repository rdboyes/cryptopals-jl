# Last challenge of the set now let's go

file_in = readlines("D:\\Projects\\cryptopals-jl\\data\\8.txt")

function sixteen_byte_repeats(bytes)
    blocks = Set()
    num_blocks = length(bytes) ÷ 16
    for i in 1:num_blocks
        push!(blocks, bytes[(1 + (i - 1) * 16):(16 + (i - 1) * 16)])
    end
    return !(length(blocks) == num_blocks)
end

is_repeat = []

for i in 1:length(file_in)
    append!(is_repeat, sixteen_byte_repeats(hex2bytes(file_in[i])))
end

findmax(is_repeat)
