from challenge_files.challenge_10_expected_bytes import expected_bytes as dec_expected_bytes
from utils.aes import aes_block_size, aes_cbc_decrypt, aes_cbc_encrypt
from utils.encoding import decode_b64_file, str_to_ints, pkcs7_pad_many, pkcs7_strip_many
from utils.lists import flatten, partition_all
import difflib

key_bytes = b"YELLOW SUBMARINE"
text_bytes = decode_b64_file("./challenge_files/10.txt", "one")
iv_bytes = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
text_bytes_p = partition_all(text_bytes, aes_block_size)
dec_bytes = aes_cbc_decrypt(key_bytes, text_bytes_p, iv_bytes)
dec_chars = [''.join([chr(n) for n in block]) for block in dec_bytes]

dec_result = ''.join(dec_chars)
dec_result_bytes = dec_bytes

is_challenge_solved = (dec_result_bytes == dec_expected_bytes)
print("dec_result_bytes equals dec_expected_bytes: ", is_challenge_solved, "\n\n")
print("dec_result: ", dec_result)


text_2 = "After the tour quits, I'll come back with more hits"
enc_text_bytes = str_to_ints(text_2)
enc_text_bytes_partd = partition_all(enc_text_bytes, aes_block_size)
enc_text_bytes_padded = pkcs7_pad_many(enc_text_bytes_partd, aes_block_size)
enc_bytes = aes_cbc_encrypt(key_bytes, enc_text_bytes_padded, iv_bytes)
enc_expected_bytes = [
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [184, 108, 74, 18, 243, 5, 100, 23, 169, 16, 111, 37, 59, 254, 103, 17],
    [15, 227, 135, 69, 255, 110, 225, 62, 23, 67, 164, 208, 21, 35, 220, 130],
    [82, 97, 226, 6, 210, 175, 206, 117, 166, 47, 18, 142, 120, 37, 216, 30],
    [86, 103, 167, 22, 51, 111, 174, 168, 12, 38, 81, 237, 240, 101, 222, 135]
    ]
is_enc_solved = (enc_bytes == enc_expected_bytes)
print("encryption works as expected: ", is_enc_solved)

dec_result = aes_cbc_decrypt(key_bytes, enc_bytes[1:], enc_bytes[0])
sans_padding = pkcs7_strip_many(dec_result, aes_block_size)
flat = flatten(sans_padding)
dec_result_text = ''.join([chr(n) for n in flat])
is_dec_solved = (dec_result_text == text_2)
print("decryption works as expected: ", is_dec_solved)
print("original text: ", text_2)
print("dec_result_text: ", dec_result_text)
