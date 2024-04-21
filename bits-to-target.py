def convert_bits_to_target(bits: str):
    if len(bits) != 8:
        raise Exception("Bits has to be 4 bytes!")
    target = ""
    exponent = bits[0:2]
    coefficient = bits[2:8]
    exponent_as_decimal = int(exponent, 16)

    for i in range(0, 64-(exponent_as_decimal*2)):
        target += "0"
    target += coefficient
    for i in range(0, exponent_as_decimal*2-6):
        target += "0"
    
    return target

def get_number_of_leading_zeros(bits: str):
    if len(bits) != 8:
        raise Exception("Bits has to be 4 bytes!")
    exponent = int(bits[0:2], 16)
    return 64 - exponent * 2

n1 = get_number_of_leading_zeros("1d00ffff")
print(n1)

n1 = get_number_of_leading_zeros("170689a3")
print(n1)

n1 = get_number_of_leading_zeros("1824dbe9")
print(n1)


t1 = convert_bits_to_target("1d00ffff")
print(t1)

def byte_swap(value: str):
    for i in range(0, len(value)):
        print()

def byteswap_hex_btc_to_little_endian(hex_string):
    hex_int = int(hex_string, 16)
    swapped_int = hex_int.to_bytes(4, byteorder='little').hex()
    return swapped_int

x = byteswap_hex_btc_to_little_endian("a3890617")
print(x)
# a3890617








# if (Objects.isNull(bits) || bits.length() != 8) {
#             throw new RuntimeException("The bits should be a 8 character long string");
#         }
#         final StringBuilder target = new StringBuilder();
#         final String exponent = bits.substring(0, 2);
#         final String coefficient = bits.substring(2, 8);
#         long exponentAsDecimal = Long.parseLong(exponent, 16);

#         for (int i = 0; i < 64 - (exponentAsDecimal * 2); i++) {
#             target.append("0");
#         }
#         target.append(coefficient);
#         for (int i = 0; i < exponentAsDecimal * 2 - 6; i++) {
#             target.append("0");
#         }

#         return target.toString();