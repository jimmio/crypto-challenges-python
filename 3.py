from utils.encoding import decode_hex
from utils.higher_methods import break_single_char_xor

mystery_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
mystery_str_decoded = decode_hex(mystery_str)
expected_result = ('XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX', "Cooking MC's like a pound of bacon")
result = break_single_char_xor(mystery_str_decoded)
is_solved = (result == expected_result)

print("result equals expected_result: ", is_solved)
print("result: ", result)
print("expected_result: ", expected_result)

    
