import subprocess
import os

directory_name = "TEST_CNF_FILES"
number_of_cnfs = 2
generate_cnf_command = "cbmc satcoin.c -DCBMC --dimacs --outfile {}"

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

for i in range(number_of_cnfs):
    execute_command(generate_cnf_command.format(directory_name + "/test" + str(i) + ".cnf"))
    # Change input block in satcoin.c