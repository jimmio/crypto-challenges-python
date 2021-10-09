from utils.encoding import encode_b64, decode_hex

input_hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

expected_b64_str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

result = encode_b64(decode_hex(input_hex_str))
result_str = str(result, "utf-8")

is_solved = (expected_b64_str == result_str)

print("result_str equals expected_b64_str: ", is_solved)
print("result_str: ", result_str)
print("expected_b64_str: ", expected_b64_str)

