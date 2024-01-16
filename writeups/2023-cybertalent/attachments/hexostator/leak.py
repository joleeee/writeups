import requests
import json
from base64 import b64encode, b64decode
from pprint import pprint
import pickle
import numpy as np
from PIL import Image

NORMAL = "https://mov16.cloud"
HEXOST = "https://mov16.cybertalent.no/app/304c18d6-94e2-11ee-a576-b7aaeb848687/hexostator"

cookie = {
    "name":'access_token',
    "value":'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiAiMjYxMGNmMDVmNzVmMTYwMGE5NjBiMDQzNmQxZWZhZWIiLCAiaWF0IjogMTcwMzA5OTI4MiwgImV4cCI6IDE3MDU3Nzc2ODJ9.Nk-sXfvav0K-O5LvgS9ucLbe_ephAdmedUz1HfUHbAc28VUDmkewJkcNATrud8aHJ_uiFY045hsrloierfPUUbJ7T3U_GZ4nqPqRJoGXBAqBjKl6xTyYUZmio36RVFoi9S4KXtH4GUP-IqrDl0DYdzbpR7QnMbqbZnk8LhENQwN-LnuErBMm4Gw_uVq6JtqwCBBKvfmhmx7pwDXMn_-V-6OG69X47a9rZyUJL20QxJBVSRrssY2LnbaQ-HACQQE2sWNQsguu3tOMFsfTYzXNRMEJ19WsNg0X6XgaHtR6aGUJxJ0procH-87YeN_q--pMNaOcKIxqIA_XZsnOoRZwmA',
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
                bytes = b64decode(test["printer_output"])
                text = bytes.decode("utf-16be")
                # if any(x not in "ABCEFGHIJKLMNOP" for x in text):
                # if all(0 <= ord(x) <= 0xf for x in text):
                #     print("== img ==")
                #     intensities = [x for x in bytes[1::2]]
                #     lines = [intensities[i:i+16] for i in range(0, len(intensities), 16)]
                #     for l in lines:
                #         print("".join(f"{c:x}".replace('f', ' ') for c in l))
                #     # print(intensities)
                # else:
                print(text)
            del test["printer_output"]


        if "error" in test:
            print("== ERROR ==")
            print(test['error'])
            del test['error']
        
        for k, v in test.items():
            print(f"{k} = {v}")
        

    if 'flag' in data:
        print(data['flag'])

def extract_images(tests):
    test = tests['tests'][1]
    out = test['printer_output']

    raw = b64decode(out)
    text = raw.decode("utf-16be")

    assert all(0 <= ord(x) <= 0xf for x in text)


    intensities = [x for x in raw[1::2]]
    # lines = [intensities[i:i+16] for i in range(0, len(intensities), 16)]

    images = [bytes(intensities[i:i+256]) for i in range(0, len(intensities), 256)]

    return images




## specific to this

def submit(contents):
    j = json.dumps({"binary": b64encode(contents).decode()})
    r = s.post(HEXOST, data=j, timeout=60)
    assert r.status_code == 200, r.text
    return json.loads(r.content)

with open("data.mos", "r") as f:
    weights = f.read()


# max ~15.5k
#from random import randint
#weights = ",\n".join(f"${randint(0, 100):04x}" for _ in range(15500))

#code = f"""% STD CAM:0 FPU:1 FPU:2 FPU:3 FPU:4
code = f"""% STD CAM:0

y <- #0
loop:
    CAC <- #1
    !CAS ? NIP <- #HLT

    x <- #0
    read_loop:
        PRN <- CAP

        x <- INC <- x
        ALX <- x
        ALY <- #256
        DIF ? NIP <- #read_loop
    
    y <- INC <- y

    ALX <- #4
    ALY <- y
    DIF ? NIP <- #loop


NIP <- #HLT



x: 0
y: 0
"""

bin = build(code)

print("Built.")


# print(r)
# show(r, whitelist={1})

found = set()

for i in range(2048):
    r = submit(bin)
    images = extract_images(r)
    for img in images:
        found.add(img)
    print(f"Got {len(images)} images, now {len(found)} {(i+1)*4}")

found = list(found)
with open("cheat_tmp2.bin", "wb") as f:
    pickle.dump(found, f)

for i, im in enumerate(found):
    img = np.reshape(list(im), (16, 16))

    pil = Image.fromarray(np.uint8(img) * 17, mode="L")
    pil.save(f"./cheat2/{i}.png")