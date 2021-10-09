from utils.encoding import encode_hex, str_to_ints
from utils.higher_methods import repeating_key_xor

input_str = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
key = "ICE"
input_str_bytes, key_bytes = str_to_ints(input_str), str_to_ints(key)

result = repeating_key_xor(input_str_bytes, key_bytes)
result_primed = encode_hex(result)
expected_result = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
is_solved = (result_primed == expected_result)

print("result_primed equals expected_result: ", is_solved)
print("result_primed:   ", result_primed)
print("expected_result: ", expected_result)
