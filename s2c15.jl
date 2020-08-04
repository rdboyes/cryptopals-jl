# padding validation

for_unpadding  = "ICE ICE BABY\x04\x04\x04\x04"

function ascii_to_bytes(text)
    bytes = UInt8[]

    for i in 1:length(text)
        append!(bytes, Int(text[i]))
    end

    return bytes
end

function unpad(bytes)
    to_remove = Int(last(bytes))
    valid = true
    for i in 1:to_remove
        if bytes[length(bytes) + 1 - i] != bytes[length(bytes)]
            valid = false
        end
    end
    if valid == true
        return bytes[1:(length(bytes) - to_remove)]
    else
        error("padding is not valid")
    end
end

String(unpad(ascii_to_bytes(for_unpadding)))

String(unpad(ascii_to_bytes("ICE ICE BABY\x05\x05\x05\x05")))

String(unpad(ascii_to_bytes("ICE ICE BABY\x01\x02\x03\x04")))
