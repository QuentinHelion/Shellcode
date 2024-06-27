nasm -f elf32 $1.asm && ld -m elf_i386 $1.o -o ../bin/$1 && rm $1.o
