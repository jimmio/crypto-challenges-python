from utils.aes import aes_ctr
from utils.encoding import decode_b64_file, ints_to_str
from utils.higher_methods import break_fixed_nonce_ctr
from utils.lists import flatten, partition_all, shortest

decoded_b64_strs = decode_b64_file("./challenge_files/20.txt", "many")
key = [62, 163, 90, 48, 226, 68, 20, 36, 215, 102, 23, 105, 121, 69, 74, 130]
fixed_nonce = [0 for i in range(8)]

enc_results = [aes_ctr(key, s, fixed_nonce) for s in decoded_b64_strs]
enc_results_non_empty = [res for res in enc_results if len(res) > 0]

shortest_len = len(shortest(enc_results_non_empty))
truncated_results = [res[:shortest_len] for res in enc_results_non_empty]

result = break_fixed_nonce_ctr(truncated_results)
result_str = result[1]
result_str_partitioned = partition_all(result_str, shortest_len)

original_strs = [ints_to_str(l) for l in decoded_b64_strs]
for s in original_strs: print(s)

for s in result_str_partitioned: print(s)
