import requests
import json
from base64 import b64encode, b64decode

NORMAL = "https://mov16.cloud"
HEXOST = "https://mov16.cybertalent.no/app/.../hexostator"

cookie = {
    "name":'access_token',
    "value":'...',
    # "domain":'.cybertalent.no',
}

s = requests.session()
s.cookies.set(**cookie)

def build(contents):
    data = json.dumps({"source": contents})
    r = s.post(NORMAL + "/build", data=data, timeout=1)
    r = json.loads(r.content)

    if 'error' in r:
        raise Exception(f"Build failed: {r['error']}")
    return b64decode(r['binary'])

def show(data, dbg=True, printer=True, whitelist={}):
    if 'flag' in data:
        print(data['flag'])

    for i, test in enumerate(data['tests']):
        if 'input' in test:
            del test['input']
        # if len(whitelist) and i not in whitelist:
        #     continue
        print(f"== TEST {i} ==")

        if "debug_output" in test:
            if dbg:
                print("== DBG ==")
                print(test['debug_output'])
            del test["debug_output"]

        if "printer_output" in test:
            if printer:
                print("== PRINTER ==")
                print(b64decode(test["printer_output"]).decode("utf-16be"))
            del test["printer_output"]


        if "error" in test:
            print("== ERROR ==")
            print(test['error'])
            del test['error']
        
        for k, v in test.items():
            print(f"{k} = {v}")
        

    if 'flag' in data:
        print(data['flag'])

## specific to this

def submit(contents):
    j = json.dumps({"binary": b64encode(contents).decode()})
    r = s.post(HEXOST, data=j, timeout=60)
    assert r.status_code == 200, r.text
    return json.loads(r.content)

def show_submission(out):
    print("== OUTPUT ==")
    print(b64decode(out['printer_output']).decode("utf-16be"))
    del out['printer_output']

    if 'error' in out:
        print("== ERROR ==")
        print(out['error'])
        del out['error']
    
    
    for k, v in out.items():
        print(f"{k} = {v}")

with open("data.mos", "r") as f:
    weights = f.read()

code = f"""% STD CAM:0

loop:
    CAC <- #1
    !CAS ? NIP <- #HLT

    x <- #0
    read_loop:
        ALX <- #img
        ALY <- x
        *SUM <- CAP

        x <- INC <- x
        ALX <- x
        ALY <- #256
        DIF ? NIP <- #read_loop
    
    wi <- #0
    we <- #weights
    statptr <- #stats
    maxstat <- FIF <- #$FFFF
    maxstati <- #0
    weight_loop:
        s <- FIF <- #0

        y <- #0
        imgp <- #img
        calc_loop:

            w <- *we
            px <- FIF <- *imgp

            FPX <- w
            FPY <- px

            RES <- FPR

            FPX <- RES
            FPY <- s

            s <- FSM

            we <- INC <- we
            imgp <- INC <- imgp

            y <- INC <- y

            ALX <- y
            ALY <- #256
            DIF ? NIP <- #calc_loop

        *statptr <- s

        FPX <- s
        FPY <- maxstat

        FLT ? NIP <- #not_better
        maxstat <- s
        maxstati <- wi


        not_better:


        statptr <- INC <- statptr
        wi <- INC <- wi
        ALX <- wi
        ALY <- #16
        DIF ? NIP <- #weight_loop
    
    ALX <- #alph
    ALY <- maxstati
    PRN <- *SUM
    
    NIP <- #loop


NIP <- #HLT



a: $4aaf

x: 0
wi: 0
y: 0
s: 0
w: 0

we: 0

imgp: 0
px: 0

statptr: stats
maxstat: 0
maxstati: 0

alph: 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P'


stats:
0,0,0,0,
0,0,0,0,
0,0,0,0,
0,0,0,0

img:
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0

weights: {weights}
"""

bin = build(code)

print("Built.")

r = submit(bin)

# print(r)
show(r, whitelist={1})