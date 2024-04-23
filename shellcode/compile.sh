nasm -f elf32 reverse_tcp.asm && ld -m elf_i386 reverse_tcp.o -o ../bin/reverse_tcp && rm reverse_tcp.o
