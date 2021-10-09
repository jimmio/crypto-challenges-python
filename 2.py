from utils.encoding import decode_hex, encode_hex
from utils.xor import xor_lists

str_a = "1c0111001f010100061a024b53535009181c"
str_b = "686974207468652062756c6c277320657965"
str_a_decoded = decode_hex(str_a)
str_b_decoded = decode_hex(str_b)

result = xor_lists(str_a_decoded, str_b_decoded)
result_primed = encode_hex(result)
expected_result = "746865206b696420646f6e277420706c6179"
is_solved = (result_primed == expected_result)

print("result_primed equals expected_result: ", is_solved)
print("result_primed: ", result_primed)
print("expected_result: ", expected_result)
