from utils.aes import aes_ctr
from utils.encoding import decode_b64, ints_to_str, str_to_ints

enc_str = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
enc_bytes = decode_b64(enc_str)
key = str_to_ints("YELLOW SUBMARINE")
nonce = [0,0,0,0,0,0,0,0]

expected_result_str = "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
result_bytes = aes_ctr(key, enc_bytes, nonce)
result_str = ints_to_str(result_bytes)
is_solved = (result_str == expected_result_str)

print("\n\nresult_str equals expected_result_str: ", is_solved)
print("\nresult_str: ", result_str)
print("\nexpected_result_str: ", expected_result_str, "\n\n")
