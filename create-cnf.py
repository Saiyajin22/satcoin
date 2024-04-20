import subprocess
import os

blocks_file = "blks.txt"
blocks_lines = []
satcoin_c = "scoin.c"
satcoin_lines = []
directory_name = "TEST_CNF_FILES"
generate_cnf_command = "cbmc scoin.c -DCBMC --dimacs --outfile {}"
# Lines to replace (starting from 0-based index)
start_line = 185  # Line 186 in the file
end_line = 204  # Line 205 in the file
verify_hash_line = 205

def execute_command_and_save_result(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        print("Command output:")
        print(result.stdout)
        
        # Print any errors
        if result.stderr:
            print("Errors:")
            print(result.stderr)
        
        # Print the return code
        print("Return code:", result.returncode) 

        return result
    except Exception as e:
        print("An Exception occurred:", e)

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

# Read satcoin.c
with open(satcoin_c, "r") as file:
    satcoin_lines = file.readlines()

for i in range(len(blocks_lines)//20):
    if(len(blocks_lines) < i*20+1): break
    # Change input block in satcoin.c
    satcoin_lines[start_line:end_line+1] = blocks_lines[i*20:(i+1)*20]
    # Change verifyHash in satcoin.c
    block_name = blocks_lines[i*20].split(" ")[2]
    block_name = block_name.split("[")[0]
    satcoin_lines[verify_hash_line] = "int main(int argc, void *argv[]){verifyhash(&" + block_name + "[0]); return 0;}"
    # Write the new c file back to satcoin.c
    with open(satcoin_c, "w") as file:
        file.writelines(satcoin_lines)
    
    # Execute cnf generation
    execute_command(generate_cnf_command.format(directory_name + "/" + block_name + ".cnf"))

print("CNF files generation ended")