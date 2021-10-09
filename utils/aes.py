from collections import Counter
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from .encoding import decode_b64, pkcs7_pad_many, str_to_ints
from .lists import append_rand_bytes, flatten, index_duplicate, is_list, partition_all
from .numbers import round_up_nearest_int
from os import urandom
from .xor import xor_lists

backend = default_backend()
aes_block_size = 16

###########
# AES-ECB #
###########

def aes_ecb_encrypt(key_bytes, text_bytes):
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    result = encryptor.update(text_bytes) + encryptor.finalize()
    return [int(b) for b in result]

def aes_ecb_decrypt(key_bytes, text_bytes):
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    result = decryptor.update(text_bytes) + decryptor.finalize()
    return [int(b) for b in result]



###########
# AES-CBC #
###########

def aes_cbc_encrypt(key_bytes, text_bytes, iv_bytes):
    enc = [iv_bytes]
    with_iv = [iv_bytes] + text_bytes
    for i in range(1, len(with_iv)):
        xord = xor_lists(enc[i-1], with_iv[i])
        encd = aes_ecb_encrypt(key_bytes, xord)
        enc.append(encd)
    return enc

def aes_cbc_decrypt(key_bytes, text_bytes, iv_bytes):
    # assumes iv is excluded from text_bytes
    decrypted = [aes_ecb_decrypt(key_bytes, block) for block in text_bytes]
    text_bytes_w_iv = [iv_bytes] + text_bytes
    decrypted_w_iv = [iv_bytes] + decrypted
    xord = [xor_lists(decrypted_w_iv[i], text_bytes_w_iv[i-1]) for i in range(1, len(decrypted_w_iv))]
    return xord



###########
# AES-CTR #
###########

def aes_ctr_make_keystream(nonce_bytes, num_blocks):
    counters = [[i, 0, 0, 0, 0, 0, 0, 0] for i in range(num_blocks)]
    result = [nonce_bytes + counters[i] for i in range(num_blocks)]
    return result

def aes_ctr(key_bytes, text_bytes, nonce_bytes):
    num_keystream_blocks = round_up_nearest_int(len(text_bytes) / aes_block_size)
    pre_keystream_blocks = aes_ctr_make_keystream(nonce_bytes, num_keystream_blocks)
    keystream = flatten([aes_ecb_encrypt(key_bytes, block) for block in pre_keystream_blocks])
    return xor_lists(text_bytes, keystream)



def gen_rand_key_bytes():
    return urandom(aes_block_size)

def detect_ecb_or_cbc(byte_lists):
    dupes = index_duplicate(byte_lists)
    if len(dupes) > 0:
        return "\n\nDuplicate block found: Encrypted in ECB mode.\n\n"
    else:
        return "\n\nNo duplicate blocks found.\n\n"



def get_raw_resp(oracle):
    return oracle([])

def get_oracle_block_size(oracle, raw_resp):
    return [len(oracle([0] * i)) - len(raw_resp) \
            for i in range(32) \
            if len(oracle([0] * i)) != len(raw_resp)][0]

def make_raw_prefix(broken_bytes, block_size):
    diff = block_size - (len(broken_bytes) % block_size)
    return [0 for i in range(diff-1)]

def make_dict_prefix(broken_bytes, block_size):
    diff = block_size - (len(broken_bytes) % block_size)
    pre_prefix = [0 for i in range(diff-1)]
    return flatten([pre_prefix] + broken_bytes)

def get_target_block(oracle, raw_prefix, block_size, target_block_i):
    response = oracle(raw_prefix)
    partd = partition_all(response, block_size)
    return partd[target_block_i]

def get_response_list(oracle, dict_prefix, block_size):
    response_list = [oracle(dict_prefix + [i]) for i in range(256)]
    response_list_partd = [partition_all(resp, block_size) for resp in response_list]
    return list(enumerate(response_list_partd))

def break_ecb_byte(response_list, target_block, target_block_i):
    return [char for char, response in response_list if response[target_block_i] == target_block]

def break_ecb_block(oracle, block_size, broken_bytes, target_block_i):
    for i in range(block_size):
        raw_prefix = make_raw_prefix(broken_bytes, block_size)
        target_block = get_target_block(oracle, raw_prefix, block_size, target_block_i)
        dict_prefix = make_dict_prefix(broken_bytes, block_size)
        response_list = get_response_list(oracle, dict_prefix, block_size)
        broken_byte = break_ecb_byte(response_list, target_block, target_block_i)
        broken_bytes.append(broken_byte)
    return flatten(broken_bytes)

def ecb_chosen_plaintext_attack(oracle):
    raw_resp = get_raw_resp(oracle)
    block_size = get_oracle_block_size(oracle, raw_resp)
    raw_resp_partd = partition_all(raw_resp, block_size)
    num_blocks = len(raw_resp_partd)
    broken_bytes = []
    accumd_blocks = [break_ecb_block(oracle, block_size, broken_bytes, i) \
                    for i in range(num_blocks)]
    return accumd_blocks[-1]



def get_index_and_early_prefix(oracle, block_size):
    # (for when attacker-controlled input does not comprise the
    # earliest bytes of the oracle response)
    controlled_input = []
    while len(controlled_input) < (block_size * 3):
        resp = oracle(controlled_input)
        partd = partition_all(resp, block_size)
        dupe = index_duplicate(partd)
        if len(dupe) == 0:
            controlled_input.append(0)
        else:
            prefix = controlled_input[:-32]
            return {"index": dupe[0][0], "prefix": prefix}
            break

def make_prefix_alt(pre_target_prefix, broken_bytes, block_size):
    target_block_prefix = make_raw_prefix(broken_bytes, block_size)
    return pre_target_prefix + target_block_prefix

def make_dict_prefix_alt(prefix, broken_bytes):
    return flatten([prefix] + broken_bytes)

def break_ecb_block_alt(oracle, block_size, broken_bytes, target_block_i, pre_target_prefix):
    for i in range(block_size):
        prefix = make_prefix_alt(pre_target_prefix, broken_bytes, block_size)
        target_block = get_target_block(oracle, prefix, block_size, target_block_i)
        dict_prefix = make_dict_prefix_alt(prefix, broken_bytes)
        response_list = get_response_list(oracle, dict_prefix, block_size)
        broken_byte = break_ecb_byte(response_list, target_block, target_block_i)
        broken_bytes.append(broken_byte)
    return flatten(broken_bytes)

def ecb_chosen_plaintext_attack_alt(oracle):
    # uses oracle responses that include a
    # random prefix of random bytes prior
    # to user-controlled input
    raw_resp = get_raw_resp(oracle)
    block_size = get_oracle_block_size(oracle, raw_resp)
    i_prefix = get_index_and_early_prefix(oracle, block_size)
    init_target_block_i, pre_target_prefix = i_prefix["index"], i_prefix["prefix"]
    raw_resp_partd = partition_all(raw_resp, block_size)
    num_blocks = len(raw_resp_partd)
    broken_bytes = []
    accumd_blocks = [break_ecb_block_alt(oracle, block_size, broken_bytes, i, pre_target_prefix) \
                    for i in range(init_target_block_i, num_blocks)]
    return accumd_blocks[-1]
    
def cbc_bitflipping_attack(oracle, parser, block_size):
    desired_ptext = "admin=true;"
    desired_ptext_bytes = str_to_ints(desired_ptext)
    ctext = oracle("")
    new_iv_a = [0 for i in range(len(desired_ptext))]
    new_iv_b = [n for n in ctext[0][len(desired_ptext):]]
    altered_ctext = [new_iv_a + new_iv_b] + ctext[1:]
    parser_resp = parser(altered_ctext)
    target_str = parser_resp["cookie"][0][:len(desired_ptext)]
    target_bytes = str_to_ints(target_str)
    payload_iv_pre = xor_lists(target_bytes, desired_ptext_bytes)
    payload_iv = payload_iv_pre + new_iv_b
    altered_ctext_final = [payload_iv] + ctext[1:]
    return parser(altered_ctext_final)



#############################
# cbc padding oracle attack #
#############################

def shift_byte(b, idx):
    # remove the "padding context" from the byte that resulted in valid padding,
    # or recontextualize it in the service of other padding values
    return b ^ (aes_block_size - idx)

def shift_bytes(intmd_bytes, idx):
    return [shift_byte(b, idx) for b in intmd_bytes]

def get_partial_iv(two_enc_blocks, idx):
    return two_enc_blocks[0][:idx]

def get_byte_from_valid_padding(oracle, two_enc_blocks, intmd_bytes, idx):
    print("two_enc_blocks in get_byte_from_valid_padding -- ", two_enc_blocks)
    partial_iv = get_partial_iv(two_enc_blocks, idx)
    print("partial_iv in get_byte_from_valid_padding -- ", partial_iv)
    c1 = two_enc_blocks[1]
    if len(intmd_bytes) == 0:
        return [b for b in range(256) if oracle([partial_iv + [b]] + [c1])]
    else:
        shifted = shift_bytes(intmd_bytes, idx)
        return [b for b in range(256) if oracle([partial_iv + [b] + shifted] + [c1])]

def resolve_ambiguity(oracle, two_enc_blocks, intmd_bytes, idx, possible_bytes):
    # when more than one byte results in valid padding on the oracle,
    # "move ahead" with each one and return what allows for
    # the process to proceed
    future_idx = idx - 1
    c1 = two_enc_blocks[1]
    for byte in possible_bytes:
        partial_iv = get_partial_iv(two_enc_blocks, future_idx)
        tentative_intmd_byte = [shift_byte(byte, idx)]
        result = get_byte_from_valid_padding(oracle, two_enc_blocks, tentative_intmd_byte, future_idx)
        if result: return byte

def get_intmd_byte(oracle, two_enc_blocks, intmd_bytes, idx):
    b = get_byte_from_valid_padding(oracle, two_enc_blocks, intmd_bytes, idx)
    if len(b) > 1:
        target_byte = resolve_ambiguity(oracle, two_enc_blocks, intmd_bytes, idx, b)
        return shift_byte(target_byte, idx)
    else:
        return shift_byte(b[0], idx)

def get_intmd_bytes(oracle, two_enc_blocks):
    idxs = list(reversed(range(aes_block_size)))
    intmd_bytes = []
    for idx in idxs:
        intmd_byte = get_intmd_byte(oracle, two_enc_blocks, intmd_bytes, idx)
        intmd_bytes.insert(0, intmd_byte)
    return intmd_bytes

def get_intmd_blocks(oracle, enc_cookie):
    num_blocks = len(enc_cookie)
    intmd_blocks = []
    for block_idx in range(1, num_blocks):
        two_enc_blocks = [enc_cookie[block_idx-1], enc_cookie[block_idx]]
        intmd_blocks.append(get_intmd_bytes(oracle, two_enc_blocks))
    return intmd_blocks

def cbc_padding_oracle_attack(oracle, enc_cookie):
    intmd_blocks = get_intmd_blocks(oracle, enc_cookie)
    # at this point, intmd_bytes is without the original IV, so intmd_bytes[i] is contextually
    # one block ahead of enc_cookie[i] -- exactly what we need for the xor
    return [xor_lists(enc_cookie[i], intmd_blocks[i]) for i in range(len(intmd_blocks))]
