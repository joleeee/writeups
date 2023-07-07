class Assembler(bytearray):
    def reverse(self, n):
        self += bytes([0x10, n])
    
    def xor(self):
        self += bytes([0x5])
    
    def lor(self):
        self += bytes([0x4])
    
    def getchar(self):
        self += bytes([0x8])
    
    def putchar(self):
        self += bytes([0x9])
    
    def push(self, what):
        self += bytes([0xa, what])
    
    def exit(self):
        self += bytes([0x0])
    
    def debug(self):
        self += bytes([0x28])

if __name__ == "__main__":
    keys = [198, 139, 217, 207, 99, 96, 216, 123, 216, 96, 246, 211, 123, 246, 216, 193, 207, 208, 246, 114, 99, 117, 190, 246, 127, 216, 99, 231, 109, 246, 99, 207, 246, 216, 246, 216, 99, 231, 109, 180, 136, 114, 112, 117, 184, 117]
    stack = [0] + keys[::-1]
    
    print(f"{keys  = }")
    print(f"{stack = }")
    
    asm = Assembler()
    
    # Hello msg
    asm.push(ord("\n"))
    asm.push(ord("K"))
    asm.push(ord("O"))
    asm.putchar()
    asm.putchar()
    asm.putchar()
    
    # set stuff up
    for v in stack:
        asm.push(v)
    asm.debug()
    
    # the actual procedure
    for i in range(len(keys)):
        k = keys[i]
        l = len(keys) - i + 1

        asm.push(k)
        asm.xor()
        asm.reverse(l-1)
        asm.reverse(l)
        asm.lor()
        asm.reverse(l-1)
        asm.reverse(l-2)
        asm.debug()
    
    

    asm.exit()
    open("bin.bin", "wb").write(asm)