from collections import Counter
from utils.aes import aes_ctr
from utils.encoding import decode_b64_file, ints_to_str
from utils.lists import tablify_bytes
from utils.xor import xor_lists

decoded_b64_strs = decode_b64_file("./challenge_files/19.txt", "many")
key = [204, 131, 11, 4, 206, 100, 102, 227, 92, 97, 54, 130, 207, 37, 14, 24]
fixed_nonce = [0 for i in range(8)]

enc_results = [aes_ctr(key, s, fixed_nonce) for s in decoded_b64_strs]
enc_results_non_empty = [res for res in enc_results if len(res) > 0]

keystream = [112, 216, 226, 253, 94, 232, 29, 49, 149, 70, 246, 172, 249, 183, 142, 85, 160, 60, 16, 73, 64, 87, 137, 224, 198, 36, 237, 7, 148, 133, 250, 254, 102, 238, 216, 68, 61, 15]

for byte_list in enc_results_non_empty:
    print(tablify_bytes(byte_list))
    
all_together = [xor_lists(keystream, res) for res in enc_results_non_empty]
all_together_chrs = [ints_to_str(l) for l in all_together]
for s in all_together_chrs:
    print(s)
