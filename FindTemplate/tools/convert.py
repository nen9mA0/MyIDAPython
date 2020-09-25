import pickle

input_file = "intel_reg.txt"
output_file = "intel_reg.conf"

with open(input_file) as f:
    tmp = f.read()

reglst = tmp.split(",")

num = 0
reg_dict = {}
for i in reglst:
    name = i.lstrip("\nR_")
    reg_dict[name] = num
    num += 1

print(reg_dict)

with open(output_file, "wb") as f:
    pickle.dump(reg_dict, f)