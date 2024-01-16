from PIL import Image
import numpy as np
from base64 import b64decode
import pickle

# open weight data
with open("weights.pickle", "rb") as f:
    weights = pickle.load(f)

weights = [[np.float16(w) for w in we] for we in weights]
flatw = []
for we in weights:
    flatw.extend(we)

# save as 16 bit float values for mov16
out = ",".join(f"${w.tobytes()[::-1].hex()}" for w in flatw)
with open("data.mos", "w") as f:
    f.write(out)
print("Saved weight values to data.mos")

# simulate to check how well our weights work
print("Simulation:")
with open("raw.bin", "rb") as f:
    b = f.read()
    b = [int.from_bytes(b[i:i+2]) for i in range(0, len(b), 2)]

imgs = [b[i:i+256] for i in range(0, len(b), 256)]

solution = "MENMOGFHKHLDDIIJKFOAPDPIMKNHLDEPEOCFEEKDGHCCGIDLENECNIIGDPPJNHHNJDGBCPOGLFCAPKELNEOEPIHJAFIMPDJOLIBGBBLBIDMJKFFMNIMOLNMEEEIIGMPN"

our_result = ""

mapping = {i: l for i, l in enumerate("ABCDEFGHIJKLMNOP")}

stats = [0] * 16

for idx, im in enumerate(imgs):

    for wi in range(16):
        weights = flatw[wi*256:]
        s = 0

        for i in range(256):
            w = weights[i]
            px = im[i]
            s += w * px

        stats[wi] = s
    
    highest = max(stats)

    for si, s in enumerate(stats):
        if s == highest:
            # print(mapping[si], end="")
            our_result += mapping[si]
            break

print("correct solution", our_result)
print("our solution    ", solution)