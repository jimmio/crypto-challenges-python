from utils.encoding import str_to_ints
from utils.higher_methods import hamming_dist

hamming_string_a, hamming_string_b = "this is a test", "wokka wokka!!!"
hamming_bytes_a = str_to_ints(hamming_string_a)
hamming_bytes_b = str_to_ints(hamming_string_b)

hamming_result = hamming_dist(hamming_bytes_a, hamming_bytes_b)
expected_hamming_result = 37
is_hamming_accurate = (hamming_result == expected_hamming_result)

print("hamming_result equals expected_hamming_result: ", is_hamming_accurate)
print("hamming_result:          ", hamming_result)
print("expected_hamming_result: ", expected_hamming_result)
