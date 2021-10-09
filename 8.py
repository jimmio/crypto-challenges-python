from collections import Counter
from utils.lists import partition_all

hex_file = open("./challenge_files/8.txt", "r")
hex_file_strs = [s for s in hex_file]
partitioned = [partition_all(s, 32) for s in hex_file_strs]
counted = [Counter(block_lst) for block_lst in partitioned]
zipped = list(zip(hex_file_strs, counted))
strs_w_reps = [[item[0] for n in item[1].values() if n > 1] for item in zipped]
not_empty = lambda x: len(x) != 0
remove_empty = list(filter(not_empty, strs_w_reps))

result = remove_empty[0][0]
expected_result = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a\n"
is_solved = (result == expected_result)

print("is_solved: ", is_solved)
print("result: ", result)
print("expected_result: ", expected_result)
