from utils.encoding import ints_to_str, pkcs7_strip, str_to_ints

block_size = 16

single_block_valid = [
    "ICE ICE BABY\x04\x04\x04\x04",
    "Don't go breaki\x01",
    "\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10",
    ]

expected_valid = [
    "ICE ICE BABY",
    "Don't go breaki",
    ""
    ]

single_block_invalid = [
    "ICE ICE BABY\x01\x02\x03\x04",
    "ICE ICE BABY\x05\x05\x05\x05",
    "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
    ]

expected_invalid = [True, True, True]

single_block_valid_ints = [str_to_ints(s) for s in single_block_valid]
results_valid = [pkcs7_strip(l, block_size) for l in single_block_valid_ints]
results_valid_strs = [ints_to_str(l) for l in results_valid]
valid_accepted = (expected_valid == results_valid_strs)

single_block_invalid_ints = [str_to_ints(s) for s in single_block_invalid]
results_invalid = []
for l in single_block_invalid_ints:
    try: pkcs7_strip(l, block_size)
    except ValueError: results_invalid.append(True)
invalid_rejected = (expected_invalid == results_invalid)

print("\n\nvalid padding accepted: ", valid_accepted, "\n")
print(results_valid_strs, "\n\n")
print("invalid padding rejected: ", invalid_rejected, "\n")
print(results_invalid)
