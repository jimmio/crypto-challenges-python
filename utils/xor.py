from .encoding import decode_hex, encode_hex

def xor(a, b):
    return a ^ b

def xor_lists(byte_list_a, byte_list_b):
    return list(map(xor, byte_list_a, byte_list_b))

