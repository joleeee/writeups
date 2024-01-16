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


code = """% STD

!ICO ? NIP <- #HLT

NIP <- #loop_no_space

loop:
    PRN <- #' '

    loop_no_space:
    !ICO ? NIP <- #loop_done
    chr <- IDA

    DIX <- chr
    DIY <- #16
    STT <- URE

    DIX <- UQO
    DIY <- #16
    STT <- URE

    DIX <- UQO
    DIY <- #16
    STT <- URE

    DIX <- UQO
    DIY <- #16
    STT <- URE

    RES <- #l0
    NIP <- #nibble
    l0:

    RES <- #l1
    NIP <- #nibble
    l1:

    RES <- #l2
    NIP <- #nibble
    l2:

    RES <- #l3
    NIP <- #nibble
    l3:

    cnt <- INC <- cnt
    left <- DEC <- left

    left ? NIP <- #more_left_this_line
    left <- #16
    cnt <- #0
    PRN <- #10
    NIP <- #loop_no_space

    more_left_this_line:

    ICO ? NIP <- #loop

loop_done:
!cnt ? NIP <- #no_last_newline
PRN <- #10
DBG <- #0

no_last_newline:
DBG <- #1
NIP <- #HLT

nibble:
    wrk <- STT

    !wrk ? NIP <- #c0
    wrk <- DEC <- wrk
    !wrk ? NIP <- #c1
    wrk <- DEC <- wrk
    !wrk ? NIP <- #c2
    wrk <- DEC <- wrk
    !wrk ? NIP <- #c3
    wrk <- DEC <- wrk
    !wrk ? NIP <- #c4
    wrk <- DEC <- wrk
    !wrk ? NIP <- #c5
    wrk <- DEC <- wrk
    !wrk ? NIP <- #c6
    wrk <- DEC <- wrk
    !wrk ? NIP <- #c7
    wrk <- DEC <- wrk
    !wrk ? NIP <- #c8
    wrk <- DEC <- wrk
    !wrk ? NIP <- #c9
    wrk <- DEC <- wrk
    !wrk ? NIP <- #ca
    wrk <- DEC <- wrk
    !wrk ? NIP <- #cb
    wrk <- DEC <- wrk
    !wrk ? NIP <- #cc
    wrk <- DEC <- wrk
    !wrk ? NIP <- #cd
    wrk <- DEC <- wrk
    !wrk ? NIP <- #ce
    wrk <- DEC <- wrk

    cf:
        PRN <- #'F'
        NIP <- #nibble_done
    ce:
        PRN <- #'E'
        NIP <- #nibble_done
    cd:
        PRN <- #'D'
        NIP <- #nibble_done
    cc:
        PRN <- #'C'
        NIP <- #nibble_done
    cb:
        PRN <- #'B'
        NIP <- #nibble_done
    ca:
        PRN <- #'A'
        NIP <- #nibble_done
    c9:
        PRN <- #'9'
        NIP <- #nibble_done
    c8:
        PRN <- #'8'
        NIP <- #nibble_done
    c7:
        PRN <- #'7'
        NIP <- #nibble_done
    c6:
        PRN <- #'6'
        NIP <- #nibble_done
    c5:
        PRN <- #'5'
        NIP <- #nibble_done
    c4:
        PRN <- #'4'
        NIP <- #nibble_done
    c3:
        PRN <- #'3'
        NIP <- #nibble_done
    c2:
        PRN <- #'2'
        NIP <- #nibble_done
    c1:
        PRN <- #'1'
        NIP <- #nibble_done
    c0:
        PRN <- #'0'
        NIP <- #nibble_done
    
    nibble_done:
    NIP <- RES



chr: 0
wrk: 0

left: 16
cnt: 0
"""

bin = build(code)
print(bin)

out = run(bin, input="JpKS2Av4sEglyPMtYU+1Bisg83amjD1dnawW0zGYrHUhrw==")
# pprint(out)
show(out)