# YELLOW SUBMARINE
# ECB Ciphers

file_in = readlines("D:\\Projects\\cryptopals-jl\\data\\7.txt")

bytes_in = UInt8[]

for i in 1:length(file_in)
    append!(bytes_in, base64decode(file_in[i]))
end

using Nettle

dec = Decryptor("AES128", "YELLOW SUBMARINE")

plaintext = decrypt(dec, bytes_in)

String(plaintext)
