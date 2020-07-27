# profile break

input_text = "foo=bar&baz=qux&zap=zazzle"

function parse_text(text)
    split_amp = split(text, "&")
    dict = Dict{String, String}()
    for i in 1:3
        split_eq = split(split_amp[i], "=")
        dict[split_eq[1]] = split_eq[2]
    end
    return dict
end

parse_text(input_text)

function dict_to_text(dict)
    return string("email=",
                    dict["email"],
                    "&uid=",
                    dict["uid"],
                    "&role=",
                    dict["role"])
end

function profile_for(input_email)
    input_email = replace(input_email, "&"=>"")
    input_email = replace(input_email, "="=>"")
    dict = Dict("email" => input_email, "uid" => "10", "role" => "user")
    return dict_to_text(dict)
end

profile_for("rdboyes@gmail.com")

random_key = UInt8[rand(1:255) for n in 1:16]

using Nettle

enc = Encryptor("AES128", random_key)
dec = Decryptor("AES128", random_key)

function pad(bytes)
    pad_length = 16 - mod(length(bytes), 16)
    for i in 1:pad_length
        append!(bytes, pad_length)
    end
    return bytes
end

function unpad(bytes)
    to_remove = Int(last(bytes))
    return bytes[1:(length(bytes) - to_remove)]
end

function ascii_to_bytes(text)
    bytes = UInt8[]

    for i in 1:length(text)
        append!(bytes, Int(text[i]))
    end

    return bytes
end

function return_encrypted_profile(input_email)
    return encrypt(enc, pad(ascii_to_bytes(profile_for(input_email))))
end

function decrypt_and_parse_profile(bytes)
    return(parse_text(String(unpad(decrypt(dec, bytes)))))
end

profile_enc = return_encrypted_profile("rdboyes@gmail.com")

@assert decrypt_and_parse_profile(profile_enc) ==
    parse_text(profile_for("rdboyes@gmail.com"))

# the role is the final thing, so we need the final block to be admin followed
# by padding

admin_block = pad(ascii_to_bytes("admin"))

# this is going to be inserted in our email address to create the block we need
# the strings start with 'email=' (6 characters) so we need an additional 10
# characters before

first_email_submission = [UInt8[0x62 for n = 1:10]; admin_block]

first_ciphertext = return_encrypted_profile(String(first_email_submission))

# the correctly padded admin block is the second block of the ciphertext

encrypted_admin_block = first_ciphertext[17:32]

# now we just need a valid encrypted profile to swap with

# email=rdb@gmail. | block one, keep
# com&uid=10&role= | block two, keep
# user             | block three, swap with valid admin block

second_ciphertext = return_encrypted_profile("rdb@gmail.com")

admin_ciphertext = [second_ciphertext[1:32]; encrypted_admin_block]

admin_profile = decrypt_and_parse_profile(admin_ciphertext)

print(admin_profile)
