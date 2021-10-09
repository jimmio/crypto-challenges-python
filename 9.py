from utils.encoding import pkcs7_pad, ints_to_str, str_to_ints

s = "YELLOW SUBMARINE"
block_len = 20
s_bytes = str_to_ints(s)

result = pkcs7_pad(s_bytes, block_len)
result_str = ints_to_str(result)
expected_result = "YELLOW SUBMARINE\x04\x04\x04\x04"

is_solved = (result_str == expected_result)
print("is_solved: ", is_solved)
print("result_str: ", result_str)
print("expected_result: ", expected_result)
