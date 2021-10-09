from utils.aes import aes_block_size, cbc_padding_oracle_attack
from utils.encoding import decode_b64, ints_to_str, pkcs7_strip_many
from utils.lists import flatten, partition_all
from utils.oracles import cbc_padding_oracle, cbc_padding_oracle_strs, cbc_provide_cookie

possible_results = [decode_b64(s) for s in cbc_padding_oracle_strs]
possible_results_strs = [''.join([chr(b) for b in res]) for res in possible_results]
possible_results_partd = [partition_all(result, aes_block_size) for result in possible_results]
cookie = cbc_provide_cookie()

actual_result = cbc_padding_oracle_attack(cbc_padding_oracle, cookie)
actual_result_stripped = flatten(pkcs7_strip_many(actual_result, aes_block_size))
actual_result_str = ints_to_str(actual_result_stripped)

print("\n\nactual_result_stripped is one of possible_results: ", (actual_result_stripped in possible_results), "\n\n")
print("actual_result_stripped as str: ", actual_result_str, "\n\n")
