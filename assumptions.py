scoin_lines = []
assumption_lines = []

with open("scoin.c", "r") as file:
    scoin_lines = file.readlines()

with open("ASSUMPTIONS.txt", "r") as file:
    assumption_lines = file.readlines()

j = 0
for i in range(152, 199):
    if(len(assumption_lines) > j):
        scoin_lines[i] = assumption_lines[j]
        j += 1
        continue
    elif(scoin_lines[i] == "\n"):
        break
    else:
        scoin_lines[i] = "\n"



# Change nonce range - line 126 in scoin
scoin_lines[125] = "__CPROVER_assume(*u_nonce > 674152120 && *u_nonce < 674153250);\n"


with open("scoin.c", "w") as file:
    file.writelines(scoin_lines)