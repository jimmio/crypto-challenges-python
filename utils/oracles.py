from .aes import aes_block_size, aes_cbc_encrypt, aes_cbc_decrypt, aes_ecb_decrypt, aes_ecb_encrypt, gen_rand_key_bytes
from .encoding import decode_b64, ints_to_str, bytes_to_int_list, pkcs7_pad_many, pkcs7_strip_many, str_to_ints
from .lists import append_rand_bytes, flatten, partition_all
from random import choice


def ecb_or_cbc_oracle(flat_bytes_list):
    key_bytes, iv_bytes = gen_rand_key_bytes(), gen_rand_key_bytes()
    rand_appended = append_rand_bytes(flat_bytes_list)
    partd = partition_all(rand_appended, aes_block_size)
    padded = pkcs7_pad_many(partd, aes_block_size)
    mode = choice([1,2])
    if (mode == 1):
        return [aes_ecb_encrypt(key_bytes, block) for block in padded]
    else:
        return aes_cbc_encrypt(key_bytes, padded, iv_bytes)




ecb_oracle_key = gen_rand_key_bytes()
rand_prefix = append_rand_bytes([])
secret_b64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

def ecb_oracle(bytes_list):    
    secret_bytes = decode_b64(secret_b64)
    secret_w_input = bytes_list + secret_bytes
    partd = partition_all(secret_w_input, aes_block_size)
    padded = pkcs7_pad_many(partd, aes_block_size)
    encrypted = [aes_ecb_encrypt(ecb_oracle_key, block) for block in padded]
    return flatten(encrypted)

def ecb_oracle_harder(bytes_list):
    secret_bytes = decode_b64(secret_b64)
    rand_appended = rand_prefix + bytes_list + secret_bytes
    partd = partition_all(rand_appended, aes_block_size)
    padded = pkcs7_pad_many(partd, aes_block_size)
    encrypted = [aes_ecb_encrypt(ecb_oracle_key, block) for block in padded]
    return flatten(encrypted)


ecb_cut_paste_key = gen_rand_key_bytes()

def parse_struc_cookie(st):
    pairs = st.split("&")
    return {k: v for k,v in [pair.split("=") for pair in pairs]}

def encode_profile(d):
    zipped = zip(d.keys(), d.values())
    paired = [str(k) + "=" + str(v) for (k,v) in zipped]
    return "&".join(paired)

def make_user_obj(email_str):
    sans = email_str.replace("&", "").replace("=", "")
    return {"email": sans,
            "uid": 10,
            "role": "user"}

def make_profile(email_str):
    user_obj = make_user_obj(email_str)
    encoded = encode_profile(user_obj)
    encoded_bytes = str_to_ints(encoded)
    partd = partition_all(encoded_bytes, aes_block_size)
    padded = pkcs7_pad_many(partd, aes_block_size)
    return [aes_ecb_encrypt(ecb_cut_paste_key, block) for block in padded]

def decrypt_parse(enc_cookie):
    dec_cookie = [aes_ecb_decrypt(ecb_cut_paste_key, block) for block in enc_cookie]
    sans_padding = pkcs7_strip_many(dec_cookie, aes_block_size)
    flat = flatten(sans_padding)
    as_str = ints_to_str(flat)
    return parse_struc_cookie(as_str)


cbc_bitflip_key = gen_rand_key_bytes()
cbc_bitflip_iv = gen_rand_key_bytes()

def cbc_bitflipping_oracle(input_str):
    pre = "comment1=cooking%20MCs;userdata="
    post = ";comment2=%20like%20a%20pound%20of%20bacon"
    sanitized = input_str.replace(";", "\;").replace("=", "\=")
    w_input = str_to_ints(pre + sanitized + post)
    partd = partition_all(w_input, aes_block_size)
    padded = pkcs7_pad_many(partd, aes_block_size)
    return aes_cbc_encrypt(cbc_bitflip_key, padded, cbc_bitflip_iv)

def cbc_bitflipping_decrypt_parse(byte_lists):
    decrypted = aes_cbc_decrypt(cbc_bitflip_key, byte_lists[1:], byte_lists[0])
    sans_padding = pkcs7_strip_many(decrypted, aes_block_size)
    flat = flatten(sans_padding)
    as_str = ints_to_str(flat)
    split_str = as_str.split(";")
    return {
        "cookie": split_str,
        "admin": ("admin=true" in split_str)
        }

######################
# cbc padding oracle #
######################
cbc_padding_oracle_key_bytes = gen_rand_key_bytes()
cbc_padding_oracle_iv_bytes = gen_rand_key_bytes()
cbc_padding_oracle_key = bytes_to_int_list(cbc_padding_oracle_key_bytes)
cbc_padding_oracle_iv = bytes_to_int_list(cbc_padding_oracle_iv_bytes)


cbc_padding_oracle_strs = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
                           "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
                           "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
                           "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
                           "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
                           "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
                           "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
                           "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
                           "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
                           "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]

def cbc_provide_cookie():
    choice_str = choice(cbc_padding_oracle_strs)
    choice_bytes = decode_b64(choice_str)
    partd = partition_all(choice_bytes, aes_block_size)
    padded = pkcs7_pad_many(partd, aes_block_size)
    return aes_cbc_encrypt(cbc_padding_oracle_key, padded, cbc_padding_oracle_iv)

def cbc_padding_oracle(enc_cookie):
    result = aes_cbc_decrypt(cbc_padding_oracle_key, enc_cookie[1:], enc_cookie[0])
    try:
        pkcs7_strip_many(result, aes_block_size)
        return True
    except ValueError:
        return False
        
