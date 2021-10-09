from .encoding import ints_to_str, str_to_ints
from .freq import score, score_bigrams
from .lists import flatten, partition_all, transpose
from .oracles import ecb_or_cbc_oracle, ecb_oracle
from .xor import xor_lists

def break_single_char_xor(byte_list):
    input_len = len(byte_list)
    ascii_ext = [[i] * input_len for i in range(256)]
    xor_results = [(ints, xor_lists(byte_list, ints)) for ints in ascii_ext]
    scored = [(score(result[1]), result[0], result[1]) for result in xor_results]
    target_result = sorted(scored)[-1]
    target_key = ints_to_str(target_result[1])
    target_str = ints_to_str(target_result[2])
    return (target_key, target_str)

def break_single_char_xors(byte_lists):
    single_char_xor_results = [break_single_char_xor(byte_list) for byte_list in byte_lists]
    count_for_spaces = [(result[1].count(" "), result[0], result[1]) \
                        for result in single_char_xor_results]
    target_result = sorted(count_for_spaces)[-1]
    return (target_result[1], target_result[2])

def repeating_key_xor(byte_list, key_bytes):
    key_ext_list = (key_bytes * len(byte_list))[:len(byte_list)]
    return xor_lists(byte_list, key_ext_list)

def hamming_dist(byte_list_a, byte_list_b):
    xord = xor_lists(byte_list_a, byte_list_b)
    xord_bin = [bin(n) for n in xord]
    return ''.join(xord_bin).count("1")

def hamming_dists(byte_list, keysize_list):
    dists_frst_scnd = [ [k, (hamming_dist(byte_list[0:k], byte_list[k:k*2]) / k)] for k in keysize_list ]
    dists_thrd_frth = [ [k, (hamming_dist(byte_list[k*2:k*3], byte_list[k*3:k*4]) / k)] for k in keysize_list ]
    averaged = [(dists_frst_scnd[i][0], ((dists_frst_scnd[i][1] + dists_thrd_frth[i][1]) /  2)) \
                for i in range(len(keysize_list))]
    sort_by = lambda l: l[1]
    return sorted(averaged, key=sort_by)

def break_repeating_key_xor(byte_list):
    keysize_list = list(range(2, 41))
    dists = hamming_dists(byte_list, keysize_list)
    target_keysizes = [a for a,b in dists[0:6]]

    partitioned = [partition_all(byte_list, size) for size in target_keysizes]
    transposed = [transpose(lst) for lst in partitioned]

    keys_transposed = [[break_single_char_xor(trans_lst) for trans_lst in lst] for lst in transposed]
    possible_key_chars = [[tup[0] for tup in lst] for lst in keys_transposed]
    possible_keys = [''.join([s[0] for s in lst]) for lst in possible_key_chars]
    possible_keys_bytes = [str_to_ints(s) for s in possible_keys]
    xor_results = [repeating_key_xor(byte_list, k) for k in possible_keys_bytes]
    xor_results_strs = [ints_to_str(lst) for lst in xor_results]
    scores = [score(lst) for lst in xor_results]
    scores_keys_strs = list(zip(scores, possible_keys, xor_results_strs))
    sort_by = lambda x: x[0]
    return sorted(scores_keys_strs, key=sort_by)[-1]

def break_fixed_nonce_ctr(byte_lists):
    transposed = transpose(byte_lists)
    keystream_chars = [break_single_char_xor(lst)[0][0] for lst in transposed]
    keystream = [ord(c) for c in keystream_chars]
    flattened = flatten(byte_lists)
    xord = repeating_key_xor(flattened, keystream)
    xord_str = ints_to_str(xord)
    return (keystream_chars, xord_str)

