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
    return r['binary']

def run(binary, input=""):
    data = json.dumps({"binary": binary, "input": {'13': input}})
    res = s.post(URL + "/run", data=data)
    res = json.loads(res.content)

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


code = """% MIN

p2 <- INC <- p3
p1 <- INC <- p2
p0 <- INC <- p1

x <- #10000
i <- #0
xloop:
    !x ? NIP <- #xloopdone

    fizzed_or_buzzed <- #0

    NIP <- #increment
    ret_adr_inc:

    NIP <- #increment_fizz
    ret_adr_inc_fizz:

    fizz ? NIP <- #nofizz
    fizzed_or_buzzed <- #1
    NIP <- #print_fizz
    ret_adr_print_fizz:
    nofizz:

    buzz ? NIP <- #nobuzz
    fizzed_or_buzzed <- #1
    NIP <- #print_buzz
    ret_adr_print_buzz:
    nobuzz:

    fizzed_or_buzzed ? NIP <- #skip_print
    NIP <- #print
    ret_adr_print:
    NIP <- #xloop_inc

    skip_print:
    PRN <- #10

    xloop_inc:
    x <- DEC <- x
    NIP <- #xloop

xloopdone:

NIP <- #HLT

ptr <- #string
loop:
        !*ptr ? NIP <- #HLT
        PRN <- *ptr
        ptr <- INC <- ptr
        NIP <- #loop

increment_fizz:
    !fizz ? NIP <- #reset_fizz
    fizz <- DEC <- fizz
    NIP <- #done_fizz
    reset_fizz:
        fizz <- #2
    done_fizz:

    !buzz ? NIP <- #reset_buzz
    buzz <- DEC <- buzz
    NIP <- #done_buzz
    reset_buzz:
        buzz <- #4
    done_buzz:

    NIP <- #ret_adr_inc_fizz

increment:
    i <- INC <- i

    ; remove leading zeros
    !l1 ? NIP <- #skip_leading1
    l1 <- DEC <- l1
    skip_leading1:

    !l2 ? NIP <- #skip_leading2
    l2 <- DEC <- l2
    skip_leading2:

    !l3 ? NIP <- #skip_leading3
    l3 <- DEC <- l3
    skip_leading3:


    leading_done:

    ; if --c0 == 0, increment 
    c0 <- DEC <- c0
    *p0 <- INC <- *p0
    c0 ? NIP <- #dont_fix_0

    ; aka increment next one
    fix_0:
        c0 <- #10
        *p0 <- #'0'

        c1 <- DEC <- c1
        *p1 <- INC <- *p1
        c1 ? NIP <- #dont_fix_1

        fix_1:
            c1 <- #10
            *p1 <- #'0'
            
            c2 <- DEC <- c2
            *p2 <- INC <- *p2
            c2 ? NIP <- #dont_fix_2

            fix_2:
                c2 <- #10
                *p2 <- #'0'
                
                c3 <- DEC <- c3
                *p3 <- INC <- *p3
                c3 ? NIP <- #dont_fix_3

                dont_fix_3:
            dont_fix_2:
        dont_fix_1:
    dont_fix_0:

    NIP <- #ret_adr_inc

print:
    ptr <- #nums

    !l1 ? NIP <- #skip1
    ptr <- INC <- ptr
    skip1:

    !l2 ? NIP <- #skip2
    ptr <- INC <- ptr
    skip2:

    !l3 ? NIP <- #skip3
    ptr <- INC <- ptr
    skip3:

    loop_print:
        !*ptr ? NIP <- #print_done
        PRN <- *ptr
        ptr <- INC <- ptr
        NIP <- #loop_print

    print_done:
    PRN <- #10

    NIP <- #ret_adr_print

print_fizz:
    ptr <- #fizztxt

    loop_print_fizz:
        !*ptr ? NIP <- #ret_adr_print_fizz
        PRN <- *ptr
        ptr <- INC <- ptr
        NIP <- #loop_print_fizz

print_buzz:
    ptr <- #buzztxt

    loop_print_buzz:
        !*ptr ? NIP <- #ret_adr_print_buzz
        PRN <- *ptr
        ptr <- INC <- ptr
        NIP <- #loop_print_buzz


; our current number in text
nums: "0000", 0

c0: 10
c1: 10
c2: 10
c3: 10

p3: nums
p2: 0
p1: 0
p0: 0

l1: 10
l2: 100
l3: 1000

ptr:    string
string: "done", 0

fizztxt: "Fizz",0
buzztxt: "Buzz",0

fizz: 3
buzz: 5

fizzed_or_buzzed: 0

x: 0
i: 0
"""

bin = build(code)
print(bin)

out = run(bin)
# pprint(out)
show(out)