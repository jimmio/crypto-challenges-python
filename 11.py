from utils.aes import detect_ecb_or_cbc
from utils.encoding import pkcs7_pad_many, str_to_ints
from utils.oracles import ecb_or_cbc_oracle

text_bytes = str_to_ints("00000000000000000000000000000000000000000000000000000000000000000000000000000000000")
oracle_result = ecb_or_cbc_oracle(text_bytes)
ecb_or_cbc = detect_ecb_or_cbc(oracle_result)
print(ecb_or_cbc)
