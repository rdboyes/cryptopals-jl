# set 2 challenge 9

# create a pkcs padding function

function ascii_to_bytes(text)
    bytes = UInt8[]

    for i in 1:length(text)
        append!(bytes, Int(text[i]))
    end

    return bytes
end

input_bytes = ascii_to_bytes("YELLOW SUBMARINE")

function pad(bytes, new_length)
    pad_length = new_length - length(bytes)
    for i in 1:pad_length
        append!(bytes, pad_length)
    end
    return bytes
end

target = "YELLOW SUBMARINE\x04\x04\x04\x04"

@assert target == String(pad(input_bytes, 20))
