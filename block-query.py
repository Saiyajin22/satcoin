import requests
import time

url = "https://api.blockchair.com/bitcoin/raw/block/{}"

# Read the blocks and store them
with open('blks.txt', "w") as file:
    file.writelines("")
    for i in range(780000, 780100):
        response = requests.get(url.format(str(i)))
        if response.status_code == 200:
            json_response = response.json()
            raw_block = ""
            if(i == 0):
                raw_block = json_response["data"][0]["raw_block"]
            else:
                raw_block = json_response["data"][str(i)]["raw_block"]

            # Write block to file
            raw_block = raw_block[0:160]
            print("Raw hex data for block at height " + str(i) + ": ", raw_block)
            block_lines = []
            for j in range(1, 21):
                if(j == 1):
                    block_lines.append("unsigned int block_" + str(i) + "[20] = {0x" + raw_block[(j-1)*8:j*8] + ",\n")
                    # file.write("unsigned int block_" + str(i) + " = {" + raw_block[(j-1)*8:j*8] + ",")
                elif(j == 20):
                    block_lines.append("0x" + raw_block[(j-1)*8:j*8]+"};\n")
                    # file.write(raw_block[(j-1)*8:j*8]+"};")
                else:
                    block_lines.append("0x" + raw_block[(j-1)*8:j*8]+",\n")
                    # file.write(raw_block[(j-1)*8:j*8]+",")
            file.writelines(block_lines)
        else:
            print("Failed to retrieve block data at height " + str(i) + ": ", response.json())
        time.sleep(1)