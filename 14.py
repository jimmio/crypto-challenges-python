from utils.aes import ecb_chosen_plaintext_attack_alt
from utils.encoding import ints_to_str
from utils.oracles import ecb_oracle_harder

expected_result = """Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n\x01"""
result = ecb_chosen_plaintext_attack_alt(ecb_oracle_harder)
result_str = ints_to_str(result)

is_solved = (result_str == expected_result)
print("\n\nis_solved: ", is_solved)
print("\n\nresult_str:\n", result_str)
print("\n\nexpected_result:\n", expected_result, "\n\n")
