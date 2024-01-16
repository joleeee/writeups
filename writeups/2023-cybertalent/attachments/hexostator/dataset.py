from PIL import Image
import numpy as np
from base64 import b64decode
import os
import pickle

def get():
    alph = "ABCDEFGHIJKLMNOP"
    mapping = {l: d for d, l in enumerate(alph)}

    with open("raw.bin", "rb") as f:
        b = f.read()

    b = [int.from_bytes(b[i:i+2]) for i in range(0, len(b), 2)]

    solution = "MENMOGFHKHLDDIIJKFOAPDPIMKNHLDEPEOCFEEKDGHCCGIDLENECNIIGDPPJNHHNJDGBCPOGLFCAPKELNEOEPIHJAFIMPDJOLIBGBBLBIDMJKFFMNIMOLNMEEEIIGMPN"
    solution = [mapping[l] for l in solution]

    imgs = [b[i:i+256] for i in range(0, len(b), 256)]

    all = list(zip(imgs, solution))
    return all

def cheat():
    with open("./exphiltrated.pickle", "rb") as f:
        src = pickle.load(f)
    
    src = [list([b for b in d]) for d in src]
    # print(src[0])
    
    imgs = []
    sols = []

    alph = "ABCDEFGHIJKLMNOP"
    mapping = {l: d for d, l in enumerate(alph)}

    for a in alph:
        dir = f"./cheat_sort/{a}"
        for file in os.listdir(dir):
            if ".png" not in file:
                continue
            nr = int(file.removesuffix(".png"))

            imgs.append(src[nr])
            sols.append(mapping[a])
    
    return list(zip(imgs, sols))


if __name__ == "__main__":
    cheat()
    # for a, b in cheat():
    #     print(a, b)
    # for a, b in get():
    #     print(a, b)
