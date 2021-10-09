from utils.encoding import decode_hex_file
from utils.higher_methods import break_single_char_xors

byte_lists = decode_hex_file("./challenge_files/4.txt", "many")
result = break_single_char_xors(byte_lists)
expected_result = ('555555555555555555555555555555', 'Now that the party is jumping\n')
is_solved = expected_result == result

print("expected_result equals result: ", is_solved)
print("result: ", result)
print("expected_result:", expected_result)
