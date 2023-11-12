org = open("program", "rb").read()

# cutoff after input part
program = org[:0x971]

insert = []
# since the code is the same for all characters, we can insert statements at regular intervals
for i in range(3):
    insert.append(0xa7 + i * 50)

out = bytes()
for i in range(len(program)):
    if i in insert:
        out += bytes([0x28])
    out += program[i:i+1]


#out += bytes([0x28]) # DEBUG
out += bytes([0]) # EXIT (prevents error)

open("password_debug", "wb").write(out)