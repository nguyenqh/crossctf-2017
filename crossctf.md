# Preparation for Cross CTF

## Binary Analysis
### Quick TODO list:
* `$ strings bin_file`
* `$ checksec bin_file`
* `$ r2 bin_file`
### Information collection
Protections can be checked using `checksec <file>`.
#### Header information

Sections of interest include `
#### PLT table
Relocation entries of the binary can be read using `readelf --relocs <file>`. For example, below shown the `.plt` table of a binary file named `1_records`,
```
$ readelf --relocs 1_records 

Relocation section '.rel.dyn' at offset 0x2dc contains 1 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
08049ffc  00000506 R_386_GLOB_DAT    00000000   __gmon_start__

Relocation section '.rel.plt' at offset 0x2e4 contains 5 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
0804a00c  00000107 R_386_JUMP_SLOT   00000000   read@GLIBC_2.0
0804a010  00000207 R_386_JUMP_SLOT   00000000   printf@GLIBC_2.0
0804a014  00000307 R_386_JUMP_SLOT   00000000   malloc@GLIBC_2.0
0804a018  00000407 R_386_JUMP_SLOT   00000000   puts@GLIBC_2.0
0804a01c  00000607 R_386_JUMP_SLOT   00000000   __libc_start_main@GLIBC_2.0
```

The address of the `@plt` symbols can be obtained with the command `elfsymbol` inside `gdb-peda`,
```
gdb-peda$ elfsymbol
Found 5 symbols
read@plt = 0x8048340
printf@plt = 0x8048350
malloc@plt = 0x8048360
puts@plt = 0x8048370
__libc_start_main@plt = 0x8048380
```
#### GOT table
To view the `.got` table during runtime, use `gdb`. Note that the table is filled using *lazy binding*, so an entry is patched only after the function has been invoked.

The address of `.got.plt` is included in the header information, which, in turn, can be obtained with `readelf` command inside `gdb-peda`. 
```
gdb-peda$ readelf
.interp = 0x8048154
.note.ABI-tag = 0x8048168
.note.gnu.build-id = 0x8048188
.gnu.hash = 0x80481ac
.dynsym = 0x80481cc
.dynstr = 0x804824c
.gnu.version = 0x80482aa
.gnu.version_r = 0x80482bc
.rel.dyn = 0x80482dc
.rel.plt = 0x80482e4
.init = 0x804830c
.plt = 0x8048330
.plt.got = 0x8048390
.text = 0x80483a0
.fini = 0x80485f4
.rodata = 0x8048608
.eh_frame_hdr = 0x8048638
.eh_frame = 0x8048664
.init_array = 0x8049f08
.fini_array = 0x8049f0c
.jcr = 0x8049f10
.dynamic = 0x8049f14
.got = 0x8049ffc
.got.plt = 0x804a000
.data = 0x804a020
.bss = 0x804a028
```




### Shared library analysis
#### determine which libraries are loaded
use the function `vmm` of `gdb-peda`

#### function offset calculation
use `libc-database` utility:
```
~/repos/libc-databse$ ./identify /lib/i386-linux-gnu/libc-2.24.so 
id local-7d12755d338fc29914025e9b9eaa739ece56b8b7
~/repos/libc-databse$ ./dump local-7d12755d338fc29914025e9b9eaa739ece56b8b7
offset___libc_start_main_ret = 0x18276
offset_system = 0x0003ab30
offset_dup2 = 0x000d74e0
offset_read = 0x000d6cd0
offset_write = 0x000d6d40
offset_str_bin_sh = 0x15ce48
```
or use the one-liner
```
~/repos/libc-databse$ ./dump `./identify /lib/i386-linux-gnu/libc-2.24.so | cut -d" " -f2`
offset___libc_start_main_ret = 0x18276
offset_system = 0x0003ab30
offset_dup2 = 0x000d74e0
offset_read = 0x000d6cd0
offset_write = 0x000d6d40
offset_str_bin_sh = 0x15ce48
```

Another tool that can be used is `objdump` in combination with `grep`, but this requires the exact function name in the library
```
$ objdump -D /lib/i386-linux-gnu/libc-2.24.so | grep "<_IO_puts@@GLIBC_2.0>:"
0005f870 <_IO_puts@@GLIBC_2.0>:
$ objdump -D /lib/i386-linux-gnu/libc-2.24.so | grep "<__read@@GLIBC_2.0>:"
000d6cd0 <__read@@GLIBC_2.0>:
```

### Cheat sheets
#### Find the loaded address of a shared function
- Find `read@plt`:
```
gdb-peda$ elfsymbol
Found 5 symbols
read@plt = 0x8048340
printf@plt = 0x8048350
malloc@plt = 0x8048360
puts@plt = 0x8048370
__libc_start_main@plt = 0x8048380
```

- Find the mapping `read@plt` - `read@got.plt`:
```
gdb-peda$ disas 0x8048340
Dump of assembler code for function read@plt:
   0x08048340 <+0>:	jmp    DWORD PTR ds:0x804a00c
   0x08048346 <+6>:	push   0x0
   0x0804834b <+11>:	jmp    0x8048330
End of assembler dump.
```
The address `0x804a00c` is that of `read@got.plt` (check that it is an address inside the `.got.plt` section). 
- Find `read@libc`:
To obtained the address where `read@libc` is loaded, simply check
```
gdb-peda$ x/wx 0x804a00c
0x804a00c:	0xf7ecfcd0
```
Confirm that `0xf7ecfcd0` is where the `read@libc` is loaded:
```
gdb-peda$ disas 0xf7ecfcd0
Dump of assembler code for function read:
   0xf7ecfcd0 <+0>:	cmp    DWORD PTR gs:0xc,0x0
   0xf7ecfcd8 <+8>:	jne    0xf7ecfd00 <read+48>
   0xf7ecfcda <+10>:	push   ebx
   0xf7ecfcdb <+11>:	mov    edx,DWORD PTR [esp+0x10]
   0xf7ecfcdf <+15>:	mov    ecx,DWORD PTR [esp+0xc]
   0xf7ecfce3 <+19>:	mov    ebx,DWORD PTR [esp+0x8]
   0xf7ecfce7 <+23>:	mov    eax,0x3
   0xf7ecfcec <+28>:	call   DWORD PTR gs:0x10
   0xf7ecfcf3 <+35>:	pop    ebx
   0xf7ecfcf4 <+36>:	cmp    eax,0xfffff001
   0xf7ecfcf9 <+41>:	jae    0xf7e11360
   0xf7ecfcff <+47>:	ret    
   0xf7ecfd00 <+48>:	call   0xf7eed480
   0xf7ecfd05 <+53>:	push   eax
   0xf7ecfd06 <+54>:	push   ebx
   0xf7ecfd07 <+55>:	mov    edx,DWORD PTR [esp+0x14]
   0xf7ecfd0b <+59>:	mov    ecx,DWORD PTR [esp+0x10]
   0xf7ecfd0f <+63>:	mov    ebx,DWORD PTR [esp+0xc]
   0xf7ecfd13 <+67>:	mov    eax,0x3
   0xf7ecfd18 <+72>:	call   DWORD PTR gs:0x10
   0xf7ecfd1f <+79>:	pop    ebx
   0xf7ecfd20 <+80>:	xchg   DWORD PTR [esp],eax
   0xf7ecfd23 <+83>:	call   0xf7eed4f0
   0xf7ecfd28 <+88>:	pop    eax
   0xf7ecfd29 <+89>:	cmp    eax,0xfffff001
   0xf7ecfd2e <+94>:	jae    0xf7e11360
   0xf7ecfd34 <+100>:	ret    
End of assembler dump.
```
- Find address of other functions in the same library:
Check the offset of the function using the `libc-database` utility (see in previous section). 
Obtain the address of the function by subtracting the offset of `read@libc` and adding the offset of the desired function.

## Debugging


### PEDA - Python Exploit Development Assistance for GDB
**Key Features:**
* Enhance the display of gdb: colorize and display disassembly codes, registers, memory information during debugging.
* Add commands to support debugging and exploit development (for a full list of commands use `peda help`):
  * `aslr` -- Show/set ASLR setting of GDB
  * `checksec` -- Check for various security options of binary
  * `dumpargs` -- Display arguments passed to a function when stopped at a call instruction
  * `dumprop` -- Dump all ROP gadgets in specific memory range
  * `elfheader` -- Get headers information from debugged ELF file
  * `elfsymbol` -- Get non-debugging symbol information from an ELF file
  * `lookup` -- Search for all addresses/references to addresses which belong to a memory range
  * `patch` -- Patch memory start at an address with string/hexstring/int
  * `pattern` -- Generate, search, or write a cyclic pattern to memory
  * `procinfo` -- Display various info from /proc/pid/
  * `pshow` -- Show various PEDA options and other settings
  * `pset` -- Set various PEDA options and other settings
  * `readelf` -- Get headers information from an ELF file
  * `ropgadget` -- Get common ROP gadgets of binary or library
  * `ropsearch` -- Search for ROP gadgets in memory
  * `searchmem|find` -- Search for a pattern in memory; support regex search
  * `shellcode` -- Generate or download common shellcodes.
  * `skeleton` -- Generate python exploit code template
  * `vmmap` -- Get virtual mapping address ranges of section(s) in debugged process
  * `xormem` -- XOR a memory region with a key