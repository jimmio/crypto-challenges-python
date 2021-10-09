from utils.oracles import decrypt_parse, make_profile

cookie = make_profile("foo@barky.admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b000")
# dictionary order in make_user_obj is not guaranteed,
# so neither is this way of implementing the attack
rearr = [0,3,2,1]
tampered = [cookie[i] for i in rearr]

result = decrypt_parse(tampered)
result_role = result["role"]
expected_result = "admin"

is_solved = (result_role == expected_result)
print("\n\nis_solved: ", is_solved)
print("result:          ", result)
print("result_role:     ", result_role)
print("expected_result: ", expected_result, "\n\n")
