import subprocess
import os

print("Welcome to create cnf script")
blocks_file = input("Please enter the name of the file which contains your blocks (!with .txt extension)\n")
scoin_c = "scoin.c"

scoin_lines = []
blocks_lines = []
directory_name = "TEST_CNF_FILES"
generate_cnf_command = "cbmc " + scoin_c + " -DCBMC --dimacs --outfile {}"
nonce_range = 500 # It will encode a nonce range twice this size, as: start = nonce - nonce_range ; end = nonce + nonce_range

# Lines to replace (starting from 0-based index)
start_line = 216  # Line 217 in the file
end_line = 235  # Line 236 in the file
verify_hash_line = 236 # Line 237 in the file

def convert_bits_to_target(bits: str):
    if len(bits) != 8:
        raise Exception("Bits has to by 4 bytes!")
    target = ""
    exponent = bits[0:2]
    coefficient = bits[2:8]
    exponent_as_decimal = int(exponent, 16)

    for i in range(0, 64-(exponent_as_decimal*2)):
        target += "0"
    target += coefficient
    for i in range(0, exponent_as_decimal*2-6):
        target += "0"
    
    return target

def byteswap_hex_btc_to_little_endian(hex_string):
    hex_int = int(hex_string, 16)
    swapped_int = hex_int.to_bytes(4, byteorder='little').hex()
    return swapped_int

def get_number_of_leading_zeros(bits: str):
    if len(bits) != 8:
        raise Exception("Bits has to be 4 bytes!")
    exponent = int(bits[0:2], 16)
    return 64 - exponent * 2

def print_assumption_lines(assumption_lines):
    for i in assumption_lines:
        print(i)

def execute_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=False, text=True)
        if result.stderr:
            print("Errors:")
            print(result.stderr)
        print("Return code:", result.returncode) 
    except Exception as e:
        print("An Exception occurred:", e)

# Program start
if not os.path.exists(directory_name):
    os.mkdir(directory_name)
    print(f"Directory '{directory_name}' created.")
else:
    print(f"Directory '{directory_name}' already exists.")

# Read the blocks and store them
with open(blocks_file, "r") as file:
    blocks_lines = file.readlines()

# Read scoin.c
with open(scoin_c, "r") as file:
    scoin_lines = file.readlines()

for i in range(len(blocks_lines)//20):
    if(len(blocks_lines) < i*20+1): break
    # Change BLOCK and verifyHash in scoin.c
    scoin_lines[start_line:end_line+1] = blocks_lines[i*20:(i+1)*20]
    block_name = blocks_lines[i*20].split(" ")[2]
    block_name = block_name.split("[")[0]
    scoin_lines[verify_hash_line] = "int main(int argc, void *argv[]){verifyhash(&" + block_name + "[0]); return 0;}"

    # Change nonce range assumption - line 126 in scoin.c
    nonce = int(blocks_lines[(i*20)+19].split("}")[0], 0)
    nonce_start = nonce - nonce_range
    nonce_end = nonce + nonce_range
    scoin_lines[125] = "__CPROVER_assume(*u_nonce > " + str(nonce_start) + " && *u_nonce < " + str(nonce_end) + ");\n"

    # Change leading zeros assumption and assertion
    bits_without_0x = blocks_lines[(i*20)+18].split("0x")[1][0:8]
    bits_without_0x_swapped = byteswap_hex_btc_to_little_endian(bits_without_0x)
    number_of_leading_zeros = get_number_of_leading_zeros(bits_without_0x_swapped)
    is_odd_leading_zeros = number_of_leading_zeros % 2 == 1

    assumption_lines = []
    assumption_lines.append("__CPROVER_assume(\n")
    state_element = 7
    state_shift = 0
    for i in range(1, number_of_leading_zeros//2+1):
        current_shift = state_shift * 8
        state_shift += 1
        if(i == number_of_leading_zeros//2-1 and not is_odd_leading_zeros):
            assumption_lines.append("(unsigned char)((state[" + str(state_element) + "] >> " + str(current_shift) + ") & 0xff) == 0x00);\n")
            if(i % 4 == 0):
                state_element -= 1
                state_shift = 0
            break
        elif(i == number_of_leading_zeros//2 and is_odd_leading_zeros):
            assumption_lines.append("(unsigned char)((state[" + str(state_element) + "] >> " + str(current_shift) + ") & 0xff) == 0x00);\n")
        else:
            assumption_lines.append("(unsigned char)((state[" + str(state_element) + "] >> " + str(current_shift) + ") & 0xff) == 0x00 &&\n")
        
        if(i % 4 == 0):
            state_element -= 1
            state_shift = 0

    # add assertion
    assumption_lines.append("int flag = 0;\n")
    current_shift = state_shift * 8
    if(is_odd_leading_zeros):
        assumption_lines.append("if ((unsigned char)(((state[" + str(state_element) + "] >> " + str(current_shift) + ") & 0xff) >> 4 & 0xf) != 0x0)\n")
    else:
        assumption_lines.append("if ((unsigned char)((state[" + str(state_element) + "] >> " + str(current_shift) + ") & 0xff) != 0x00)\n")
    assumption_lines.append("{\n")
    assumption_lines.append("   flag = 1;\n")
    assumption_lines.append("}\n")
    assumption_lines.append("assert(flag == 1);\n")

    j = 0
    for i in range(152, 198):
        if(len(assumption_lines) > j):
            scoin_lines[i] = assumption_lines[j]
            j += 1
            continue
        elif(scoin_lines[i] == "\n"):
            break
        else:
            scoin_lines[i] = "\n"

    
    # Write the new c file back to scoin.c
    with open(scoin_c, "w") as file:
        file.writelines(scoin_lines)
    
    # Execute cnf generation
    execute_command(generate_cnf_command.format(directory_name + "/" + block_name + ".cnf"))


print("CNF files generation ended")