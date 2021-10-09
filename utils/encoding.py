from .lists import all_same
import base64

def encode_hex(byte_list):
    return ''.join([format(n, 'x').zfill(2) for n in byte_list])

def decode_hex(hex_string):
    byte_array = bytearray.fromhex(hex_string)
    byte_list = [int(x) for x in byte_array]
    return byte_list

def decode_hex_file(file_path, mode):
    hex_file = open(file_path, "r")
    hex_str_separated = hex_file.read().split("\n")
    if mode == "one":
        hex_str = ''.join(hex_str_separated)
        return decode_hex(hex_str)
    if mode == "many":
        return [decode_hex(hex_str) for hex_str in hex_str_separated]

def encode_b64(byte_list):
    byte_array = bytes(byte_list)
    return base64.b64encode(byte_array)

def decode_b64(b64_string):
    bytes_from_str = base64.b64decode(b64_string)
    return [int(b) for b in bytes_from_str]

def decode_b64_file(file_path, mode):
    b64_file = open(file_path, "r")
    b64_str_separated = b64_file.read().split("\n")
    if mode == "one":
        b64_str = ''.join(b64_str_separated)
        return decode_b64(b64_str)
    if mode == "many":
        return [decode_b64(b64_str) for b64_str in b64_str_separated]

def ints_to_str(int_list):
    return ''.join([chr(n) for n in int_list])

def str_to_ints(string):
    return [ord(c) for c in string]

def bytes_to_int_list(key_bytes):
    return [int(b) for b in key_bytes]

def pkcs7_pad(byte_list, block_size):
    diff = block_size - len(byte_list)
    pad = [diff] * diff
    return byte_list + pad
    
def pkcs7_pad_many(byte_lists, block_size):
    last = byte_lists[-1]
    if len(last) < block_size:
        return byte_lists[:-1] + [pkcs7_pad(last, block_size)]
    else:
        return byte_lists + [pkcs7_pad([], block_size)]

def pkcs7_strip(byte_list, block_size):
    last_byte = byte_list[-1]
    r_start = block_size - last_byte
    target_bytes = byte_list[r_start:]
    if all_same(target_bytes) and \
       (0 < last_byte <= block_size) and \
       (len(byte_list) == block_size):
        return byte_list[:r_start]
    else:
        raise ValueError("Bad padding.")

def pkcs7_strip_many(byte_lists, block_size):
    stripped = [pkcs7_strip(byte_lists[-1], block_size)]
    return byte_lists[:-1] + stripped
