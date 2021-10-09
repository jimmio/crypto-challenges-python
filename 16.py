from utils.aes import aes_block_size, cbc_bitflipping_attack
from utils.oracles import cbc_bitflipping_decrypt_parse, cbc_bitflipping_oracle

result = cbc_bitflipping_attack(cbc_bitflipping_oracle,
                                cbc_bitflipping_decrypt_parse,
                                aes_block_size)

print("\n\nsolved: ", (result["admin"] == True))
print("result: ", result, "\n\n")
