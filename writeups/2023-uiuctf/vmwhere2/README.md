# Table of contents
- [Initial reconnaissance](#initial-reconnaissance)
- [A small note on architectures and operative systems](#a-small-note-on-architectures-and-operative-systems)
- [Reversing the elf binary](#reversing-the-elf-binary)
    - [Dissasembler](#dissasembler)
    - [The two steps](#the-two-steps)
    - [Target stack state](#target-stack-state)
    - [Finding the password](#finding-the-password)
    - [Figuring out how input characters are transformed](#figuring-out-how-input-characters-are-transformed)
    


# Initial reconnaissance
We are given an executable `chal` and a file `program`.

```sh
$ file chal
chal: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6339ea4a516f6db437ac3fc08b140d798ffb0ae1, for GNU/Linux 3.2.0, stripped
$ file program
program: data
$ ls -l program chal
-rw-r--r--@ 1 jole  staff  14472 Jul  1 13:35 chal
-rw-r--r--@ 1 jole  staff   3054 Jul  1 13:35 program
```

We guess from this information and the name of the challenge, *vmwhere*, that `chal` implements a virtual machine, and `program` is a program it can run.

```sh
$ ./chal program
Welcome to VMWhere 2!
Please enter the password:
test
sdfasdasdfasdasfasdfasdfasdfasdfasdfasdfasdfasdfasdf
Incorrect password!
```

And it seems to be the case! We also notice it apparently looks for a fixed length password, because it hangs on newline (`"test\n"`), and wants more input (`"sdfasdf..."`)

# A small note on architectures and operative systems
If you are on macos (or aarch64 linux) you can use docker to spawn an x64 linux container. I use the following command.
```sh
docker run -it --rm --entrypoint /bin/bash -v .:/host --platform linux/amd64 ubuntu
```

This also mounts the folder you run it to `/host` on the guest.

# Reversing the elf binary
We open the program in binja, and look around. It quite quickly starts to make sense, and with a few renamed variables and functions, we end up with something like this. I've removed boring stuff for brievty :)

```c
0000197c  int32_t main(int32_t argc, char** argv, char** envp)
000019a2      if (argc s<= 1)
000019bd          printf(format: "Usage: %s <program>\n", *argv)
000019c2          return 1
000019de      else
000019de          int32_t length
000019de          void* program = read_program(filename: argv[1], &length)
000019ec          if (program == 0)
00001a0b              printf(format: "Failed to read program %s\n", argv[1])
00001a10              return 2
00001a2f          else if (run(program, length) == 0)
00001a38              return 0
00001a31          else
00001a31              return 3
```

And the juicy part:
```c
0000144c  int64_t run(void* program, int32_t length)

00001463      void* pc = program
0000146c      void* stack = malloc(bytes: 0x1000)
00001479      void* sp = stack
00001950      int64_t exit_code
00001950      while (true)
00001950          if (program u<= pc && pc u< program + length)
00001482              void* _pc = pc
0000148a              pc = _pc + 1
00001491              uint32_t op = *_pc
0000149d              switch (op)
000014c0                  case 0
000014c0                      exit_code = 0
000014c5                      break
000014e7                  case 1 // various numeric methods: ADD, SUB, ...
000014e7                      *(sp - 2) = *(sp - 2) + *(sp - 1)
000014e9                      sp = sp - 1
00001512                  case 2
00001512                      *(sp - 2) = *(sp - 2) - *(sp - 1)
00001514                      sp = sp - 1
0000153b                  case 3
0000153b                      *(sp - 2) = *(sp - 2) & *(sp - 1)
0000153d                      sp = sp - 1
00001564                  case 4
00001564                      *(sp - 2) = *(sp - 2) | *(sp - 1)
00001566                      sp = sp - 1
0000158d                  case 5
0000158d                      *(sp - 2) = *(sp - 2) ^ *(sp - 1)
0000158f                      sp = sp - 1
000015c2                  case 6 // SHL
000015c2                      *(sp - 2) = (*(sp - 2) << *(sp - 1)).b
000015c4                      sp = sp - 1
000015f7                  case 7 // SHR
000015f7                      *(sp - 2) = (*(sp - 2) s>> *(sp - 1)).b
000015f9                      sp = sp - 1
0000160e                  case 8
0000160e                      *sp = getchar()
00001610                      sp = sp + 1
0000161a                  case 9
0000161a                      sp = sp - 1
0000162b                      putchar(c: *sp)
00001635                  case 0xa // PUSH
00001635                      void* next_inst = pc
0000163d                      pc = next_inst + 1
00001648                      *sp = *next_inst
0000164a                      sp = sp + 1
00001661                  case 0xb // JMP if <0
00001661                      if (*(sp - 1) s< 0)
00001686                          pc = pc + *(pc + 1) | (*pc << 8).w
0000168a                      pc = pc + 2
000016a1                  case 0xc // JUMP if ==0
000016a1                      if (*(sp - 1) == 0)
000016c6                          pc = pc + *(pc + 1) | (*pc << 8).w
000016ca                      pc = pc + 2
000016fb                  case 0xd // JUMP
000016fb                      pc = pc + *(pc + 1) | (*pc << 8).w + 2
00001705                  case 0xe  // pop
00001705                      sp = sp - 1
0000171b                  case 0xf  // dup
0000171b                      *sp = *(sp - 1)
0000171d                      sp = sp + 1
00001727                  case 0x10 // REVERSE
00001727                      void* org_pc = pc
0000172f                      pc = org_pc + 1
00001733                      uint8_t arg = *org_pc
00001739                      uint64_t _arg = arg
00001748                      if (_arg s> sp - stack)
00001764                          printf(format: "Stack underflow in reverse at 0x…", pc - program, _arg)
000017d7                      for (int32_t k = 0; k s< arg u>> 1; k = k + 1)
00001785                          char rax_100 = *(sp + k - arg)
000017b0                          *(sp + k - arg) = *(sp + not.d(k))
000017c5                          *(not.d(k) + sp) = rax_100
000017ea                  case 0x11  // SPREAD bits out [0b10110000] -> [1, 0, 1, 1, 0, 0, 0, 0]
000017ea                      uint8_t top = *(sp - 1)
00001817                      for (int32_t i = 0; i s<= 7; i = i + 1)
0000180a                          *(sp - 1 + i) = top & 1
0000180c                          top = top u>> 1
00001819                      sp = sp + 7
00001828                  case 0x12  // JOIN them back together
00001828                      char reassembled = 0
0000185e                      for (int32_t j = 7; j s>= 0; j = j - 1)
00001853                          reassembled = reassembled << 1 | (*(sp - 8 + j) & 1)
00001868                      *(sp - 8) = reassembled
0000186a                      sp = sp - 7
0000188b                  case 0x28
0000188b                      debug(program, stack, sp, pc - program)
0000149d              if (op == 1 || op == 2 || op == 3 || op == 4 || op == 5 || op == 6 || op == 7 || op == 8 || op == 9 || op == 0xa || op == 0xd || op == 0xe || op == 0xf || op == 0x28 || op == 0x10 || op == 0x11 || op == 0x12 || op == 0xb || op == 0xc)
000018d7                  if (sp u< stack)
000018f3                      printf(format: "Stack underflow at 0x%04lx\n", pc - program)
000018f8                      exit_code = 1
000018fd                      break
0000190d                  if (sp u> stack + 0x1000)
00001929                      printf(format: "Stack overflow at 0x%04lx\n", pc - program)
0000192e                      exit_code = 1
00001933                      break
0000190d                  continue
000018c0              printf(format: "Unknown opcode: 0x%02x at 0x%04l…", *(pc - 1), pc - 1 - program)
000018c5              exit_code = 1
000018ca              break
00001970          printf(format: "Program terminated unexpectedly.…", pc - program)
00001975          exit_code = 1
00001975          break
0000197b      return exit_code
```

Quite a lot to take in, but look at the most important part and use your imagination. In this case, you can just think "what makes the most sense in this case?". There are a bunch of operations like `ADD`, `SUB`, `XOR`, `PUSH`. They do what you think.

Notice the function which I've named `debug()`, it'll come in handly later.

### Dissasembler
Using this, we can write a little dissassembler. I have added spacing and pseudolabels in the output, so you can see what lines may be jumped to. This makes it easier to simplify the code for me.

```py
import ctypes
from sys import argv

program = open(argv[1], "rb").read()

# opcodes that dont have arguments (only operate on the stack)
m = {
    0: "EXIT",
    1: "ADD",
    2: "SUB",
    3: "AND",
    4: "OR",
    5: "XOR",
    6: "SHL",
    7: "SHR",
    8: "getchar()",
    9: "putchar()",
    
    0xe: "POP",
    0xf: "DUP",

    0x11: "SPREAD",
    0x12: "JOIN",
    
    0x28: "DEBUG",
}

jump_targets = {}

i = 0

def decompile_one():
    global i
    org_i = i

    b = program[i]
    try:
        return m[b]
    except:
        if b == 0xa:
            next_b = program[i+1]
            chr_v = chr(next_b)
            # show ascii character if in range
            chr_txt = f"[{chr_v}]" if chr_v.isalnum() and chr_v.isascii() else ""

            i += 1

            return f"PUSH(0x{next_b:x}) {chr_txt}"
        elif b == 0xb or b == 0xc or b == 0xd:
            # the jump offset is 16 bit, consisting of two bytes
            p1 = program[i+1]
            p2 = program[i+2]
            pt = (p1 << 8) | p2

            # it jumps two anyway, to skip the arguments (even if it jumps somewhere else...)
            pt += 3
            pt_c = ctypes.c_int16(pt).value

            end = pt_c + i

            i += 2

            mnem = {
                0xb: "JMP.LZ",
                0xc: "JMP.Z",
                0xd: "JMP",
            }[b]
            
            if not end in jump_targets:
                jump_targets[end] = []
            jump_targets[end].append(org_i)

            # use hex() so we get eg. -0x10 and not 0x-10
            return f"{mnem} rel={hex(pt_c)} abs=0x{end:x}"
        elif b == 0x10:
            arg = program[i+1]
            i += 1
            return f"REVERSE({arg})"
        else:
            print(f"unknown opcode {b:x}")
            exit(0)
    
out_lines = []

while i < len(program):
    out_lines.append((i, decompile_one()))
    i += 1

for (i, line) in out_lines:
    if i in jump_targets:
        froms = jump_targets[i]
        print("")
        print(f"-- TARGET :0x{i:04x} --  from [", ",".join(hex(x) for x in froms), "]", sep="")
    print(f"0x{i:04x}: {line}")
```

Not pretty but it works. You can read the full output [here](decompile.txt). There are a lot of lines, but by looking it at you quickly see there is repetition. We make a few observations

1. There does not seem to be any use of loops or anything similar to a while statement.
2. There are 46 cases of `getchar()`, this probably means the password is 46 characters.
3. There seems to be two parts.
    - **Input**. First, each char of the password is read in, manipulated, and then put onto the stack (as still a single byte/char).
    - **Verification**. Then, they are "recursively" combined together until there is only one element is left. If this element is 0, the flag is printed.


The first part, the **input** part, looks as follows:
```asm
-- TARGET :0x093f --  from [0x926]
0x093f: POP
0x0940: getchar()
0x0941: SPREAD
0x0942: PUSH(0xff) 
0x0944: REVERSE(9)
0x0946: REVERSE(8)
0x0948: PUSH(0x0) 

-- TARGET :0x094a --  from [0x96e]
0x094a: REVERSE(2)
0x094c: DUP
0x094d: PUSH(0xff) 
0x094f: XOR
0x0950: JMP.Z rel=0x7 abs=0x957
0x0953: POP
0x0954: JMP rel=0x7 abs=0x95b

-- TARGET :0x0957 --  from [0x950]
0x0957: POP
0x0958: JMP rel=0x19 abs=0x971 // JUMP TO NEXT CHUNK

-- TARGET :0x095b --  from [0x954]
0x095b: REVERSE(2)
0x095d: REVERSE(2)
0x095f: JMP.Z rel=0xa abs=0x969
0x0962: POP
0x0963: PUSH(0x1) 
0x0965: ADD
0x0966: JMP rel=0x4 abs=0x96a

-- TARGET :0x0969 --  from [0x95f]
0x0969: POP

-- TARGET :0x096a --  from [0x966]
0x096a: DUP
0x096b: DUP
0x096c: ADD
0x096d: ADD
0x096e: JMP rel=-0x24 abs=0x94a
```

The **verification** contains a lot of xor and stack operations, and looks as follows.
```asm
-- TARGET :0x0971 --  from [0x958]
0x0971: POP

0x0972: PUSH(0xc6) 
0x0974: XOR
0x0975: REVERSE(46)
0x0977: REVERSE(47)
0x0979: OR
0x097a: REVERSE(46)
0x097c: REVERSE(45)

0x097e: PUSH(0x8b) 
0x0980: XOR
0x0981: REVERSE(45)
0x0983: REVERSE(46)
0x0985: OR
0x0986: REVERSE(45)
0x0988: REVERSE(44)

...

0x0b82: PUSH(0xb8) 
0x0b84: XOR
0x0b85: REVERSE(2)
0x0b87: REVERSE(3)
0x0b89: OR
0x0b8a: REVERSE(2)
0x0b8c: REVERSE(1)

0x0b8e: PUSH(0x75) [u]
0x0b90: XOR
0x0b91: REVERSE(1)
0x0b93: REVERSE(2)
0x0b95: OR
0x0b96: REVERSE(1)
0x0b98: REVERSE(0)

0x0b9a: JMP.Z rel=0x6 abs=0xba0 // win
0x0b9d: JMP rel=0x1f abs=0xbbc  // lose
```

## The two steps.
We decide to work backwards. We first find out what the stack must look like for the verification part to succeed. We can then later figure out what the password must be for the stack to end up like it should.

We can simplify this expression:
```
PUSH(0x75) [u]
XOR
REVERSE(1)
REVERSE(2)
OR
REVERSE(1)
REVERSE(0)
```

To a more generic
```
PUSH(k)
XOR
REVERSE(l-1)
REVERSE(l)
OR
REVERSE(l-1)
REVERSE(l-2)
```
## Target stack state
If you have a good visual imagination you may be able to see what this does, or you can do like me and use your fingers. This may give you strange looks :)

It effectively boils down to taking the top value, xoring it with a key, and then taking binary or with the bottom value. It's equal to `stack.push( (stack.pop_top() ^ k) | stack.pop_bottom() )`.

We can start with the base case, there are 2 elements left `[b, a]` (where `[bottom, ..., top]`), and the operation needs to return 0. That is, `(a ^ k) | b` needs to be 0. This obviously means `a = k`, `b = 0`. So our stack actually looks like `[k, 0]`. If we continue this we see that to end up with 0, our stack actually just needs to look like `[0, ..., k_2, k_1, k_0]`, or `[0] + keys[::-1]`

We now know what our stack should look like for the verification step to succeed! We can verify it extracting the keys, and then writing an assembler, and then running the equivalent code.

```py
lines = open("keysrc.txt", "r").readlines()

out = []

for line in lines:
    line = line.strip()
    if not "PUSH" in line:
        continue
    
    cmd = line.split(" ")[1]
    
    nr = cmd.removeprefix("PUSH(").removesuffix(")")
    out.append(int(nr, 16))

print(out)
```

Gives us
```py
[198, 139, 217, 207, 99, 96, 216, 123, 216, 96, 246, 211, 123, 246, 216, 193, 207, 208, 246, 114, 99, 117, 190, 246, 127, 216, 99, 231, 109, 246, 99, 207, 246, 216, 246, 216, 99, 231, 109, 180, 136, 114, 112, 117, 184, 117]
```

**This is the answer to what the stack needs to look like before verification runs.**

We write the following test code, and it works.

```py
class Assembler(bytearray):
    def reverse(self, n):
        self += bytes([0x10, n])

    def xor(self):
        self += bytes([0x5])
    
    def lor(self):
        self += bytes([0x4])
    
    def getchar(self):
        self += bytes([0x8])
    
    def putchar(self):
        self += bytes([0x9])
    
    def push(self, what):
        self += bytes([0xa, what])
    
    def exit(self):
        self += bytes([0x0])
    
    def debug(self):
        self += bytes([0x28])

if __name__ == "__main__":
    keys = [198, 139, 217, 207, 99, 96, 216, 123, 216, 96, 246, 211, 123, 246, 216, 193, 207, 208, 246, 114, 99, 117, 190, 246, 127, 216, 99, 231, 109, 246, 99, 207, 246, 216, 246, 216, 99, 231, 109, 180, 136, 114, 112, 117, 184, 117]
    stack = [0] + keys[::-1]
    
    print(f"{keys  = }")
    print(f"{stack = }")
    
    asm = Assembler()
    
    # Hello msg, just to test
    asm.push(ord("\n"))
    asm.push(ord("K"))
    asm.push(ord("O"))
    asm.putchar()
    asm.putchar()
    asm.putchar()
    
    # set stuff up
    for v in stack:
        asm.push(v)
    asm.debug()
    
    # the actual procedure
    for i in range(len(keys)):
        k = keys[i]
        l = len(keys) - i + 1

        asm.push(k)
        asm.xor()
        asm.reverse(l-1)
        asm.reverse(l)
        asm.lor()
        asm.reverse(l-1)
        asm.reverse(l-2)
        asm.debug()

    asm.exit()
    open("bin.bin", "wb").write(asm)
```

```sh
$ ./chal bin.bin
...

Program counter: 0x02a4
Stack pointer: 0x0002
Stack:
0x0002: 0x00b8
0x0001: 0x0075
0x0000: 0x0000

Program counter: 0x02b1
Stack pointer: 0x0001
Stack:
0x0001: 0x0075
0x0000: 0x0000

Program counter: 0x02be
Stack pointer: 0x0000
Stack:
0x0000: 0x0000
```

And it works! On to the last (first) part.

## Finding the password
We now know what the 46 elements on the stack needs to look like, but we do not know what the password needs to be for the stack to end up like that. There is some secret transformation happening. Each character is first split into its component bytes, then a lot of stuff happens to them, before it is merged back to one byte / element again.

## Figuring out how input characters are transformed
We start by inserting debug statements into the existing program, so we can see what the stack looks like as the program runs.

Putting in debug statements might break jump statements, so be careful! They have relative offsets, so it's *possible* to *not* destroy the program, if you place them right.

You can see the code in [password_debug.py](password_debug.py). If we run it we get something like the following. Edited so it's easier to see.

```
# echo -n "aaa" | ./chal password_debug
Welcome to VMWhere 2!
Please enter the password:

Stack:
0x0004: 0x00ff
0x0003: 0x0067 // a

Stack:
0x0005: 0x00ff
0x0004: 0x0067 // a
0x0003: 0x0067 // a

Stack:
0x0006: 0x00ff
0x0005: 0x0067 // a
0x0004: 0x0067 // a
0x0003: 0x0067 // a

# echo -n "aba" | ./chal password_debug
Welcome to VMWhere 2!
Please enter the password:

Stack:
0x0004: 0x00ff
0x0003: 0x0067 // a

Stack:
0x0005: 0x00ff
0x0004: 0x006d // b
0x0003: 0x0067 // a

Stack:
0x0006: 0x00ff
0x0005: 0x0067 // a
0x0004: 0x006d // b
0x0003: 0x0067 // a
```

It turns out that previous characters do not affect future characters. In addition it does not matter when a character is typed, it is always transformed into the same byte.

We can now use the same program to actually extract the conversions. For instance we know `a` always becomes `0x67`. It's a bit of a hack, but it means we won't have to actually know whats going on! You could also reuse the assembler to write a very small program which takes one character input and prints the transformed output!


After removing duplicates and capital letters (the transformation is not ???tive), we end up with the following.

```py
m = {
    'a': 0x67, 'b': 0x6d, 'c': 0x70, 'd': 0x7f, 'e': 0x82, 'f': 0x88, 'g': 0x8b, 'h': 0xb5, 'i': 0xb8, 'j': 0xbe, 'k': 0xc1, 'l': 0xd0, 'm': 0xd3, 'n': 0xd9, 'o': 0xdc, 'p': 0x57, 'q': 0x5a, 'r': 0x60, 's': 0x63, 't': 0x72, 'u': 0x75, 'v': 0x7b, 'w': 0x7e, 'x': 0xa8, 'y': 0xab, 'z': 0xb1, '0': 0xcc, '1': 0xcf, '2': 0xd5, '3': 0xd8, '4': 0xe7, '5': 0xea, '6': 0xf0, '7': 0xf3, '8': 0x1d, '9': 0x20, '{': 0xb4, '}': 0xc6, '-': 0x48, '_': 0xf6, '#': 0xe5, '$': 0xf4, '%': 0xf7, '&': 0xfd, '*': 0x33, '(': 0x2a, ')': 0x2d, '<': 0x38, '>': 0x41, '?': 0x44, '[': 0xdb, ']': 0xed,
}

# reverse lookup table
rev = {}
for k in m:
    v = m[k]
    assert not v in rev
    rev[v] = k
```

We can now find the password by looking up the stack values from the **verification** part.

```py
stack = [0, 117, 184, 117, 112, 114, 136, 180, 109, 231, 99, 216, 246, 216, 246, 207, 99, 246, 109, 231, 99, 216, 127, 246, 190, 117, 99, 114, 246, 208, 207, 193, 216, 246, 123, 211, 246, 96, 216, 123, 216, 96, 99, 207, 217, 139, 198]

for s in stack:
    try:
        print(rev[s], end="")
    except:
        print("dunno")
```

```
$ python3 solve.py
dunno
uiuctf{b4s3_3_1s_b4s3d_just_l1k3_vm_r3v3rs1ng}
```

Oh it worked... Well that's it!