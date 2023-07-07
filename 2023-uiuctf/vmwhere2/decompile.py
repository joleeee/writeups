import ctypes
from sys import argv

program = open(argv[1], "rb").read()

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
            hex_v = hex(next_b)
            chr_v = chr(next_b)
            chr_txt = f"[{chr_v}]" if chr_v.isalnum() and chr_v.isascii() else ""

            i += 1

            return f"PUSH(0x{next_b:x}) {chr_txt}"
        elif b == 0xb or b == 0xc or b == 0xd:
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