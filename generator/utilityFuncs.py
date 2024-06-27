import random

# Generates random string for the label
def genRandomString(length):
    return "".join(random.choices('abcdefghijklmnopqrstuvwxyz', k=length))

def getRandomRegister():
    registers = ['ebx', 'ecx', 'edx', 'edi', 'esi']
    return random.choice(registers)

# A list of instructions that even if they are added they won't impact the code 
def getUnimpactfulInstructs():
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
        ["add eax, 0x01", "sub eax, 0x01"],
        ["add ebx, 0x1b", "sub ebx, 0x1b"],
        ["add ecx, 0x4c", "sub ecx, 0x4c"],
        ["add edx, 0xfd", "sub edx, 0xfd"],
        ["xchg eax, ebx", "xchg eax, ebx"],
        ["xchg ecx, edx", "xchg ecx, edx"],
        ["xchg eax, ebx", "xchg eax, ebx", "xchg ecx, edx", "xchg ecx, edx"]
    ]
    # Chooses a random number that will be the number of instructions to add 
    nbInstructs = random.randint(1, 5)
    instructs = random.sample(unimpactful_instructions, nbInstructs)
    return "\n" + "\n".join(["\n".join(instr) for instr in instructs])

def int2hex(int_val):
    return hex(int_val & 0xFFFF)[2:].zfill(2)

# checks if the given ip is a valid ipv4 address
def is_valid_ipv4(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return False
    return True

# Checks if the IP has 0 in it if yes it will be implemented as a substraction of 2 IPs that dont have a 0 in hex if not it will be converted to hex in little endian
def process_ip(ip):
    parts = list(map(int, ip.split('.')))
    if any(part == 0 for part in parts):
        transformed_parts = [255 - part for part in parts]
        hex_values = [int2hex(part) for part in transformed_parts]
        result = '0x' + ''.join(hex_values[::-1])
        return f"mov eax,0xffffffff\nmov ebx,{result}\nxor ebx,eax\npush ebx"
    else:
        hex_values = [int2hex(part) for part in parts]
        result = '0x' + ''.join(hex_values[::-1])
        return f"push {result}"

# Converts port to hex value in little endian
def process_port(port):
    inverted = f"{port:04x}"
    hexport = inverted[2:] + inverted[:2]
    return f"0x{hexport}"

