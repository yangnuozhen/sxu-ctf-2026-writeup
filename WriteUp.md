# 2026 山西大学网络安全 CTF 校赛 | 新星赛道

- WriteUp 文档仓库: [https://github.com/yangnuozhen/sxu-ctf-2026-writeup](https://github.com/yangnuozhen/sxu-ctf-2026-writeup)
- 包含题目: 
    - Crypto: 1, 2, 3
    - Misc: 2, 3
    - Pwn: 1, 2
    - Reverse: 2, 3
    - Web: 1, 2, 3

> 由于部分题目的靶机在比赛结束后无法连接，故部分复现截图缺失...

## Crypto 方向

### 01.关键的Vigenere

#### 初步分析

题目明确给出了维基尼亚密码 Vigenere，提示里亦给出了 Keyword ，也就是关键词替换密码。故考虑两种密码。

注意到下方的 `qzsz{bl@rstpb_ibgfrg!}` 显然是 Flag 的结构，故仅替换英文字母，其他字符原样保留。然后假设前四个字母 `qzsz` 对应 `flag`，反推得密钥的前四个字母为 `LOST`。

又云「观其表，解其里」，更合适的切入点是先构造关键词替换表，解开上方短句中的提示。

#### Keyword 解密

尝试使用关键的 `VIGENERE` 作为关键词，得到

```plain
明文字母表：ABCDEFGHIJKLMNOPQRSTUVWXYZ
密文字母表：VIGENRABCDFHJKLMOPQSTUWXYZ
```

进一步，解密上方短句，得 `KEY IS LOSTDREAM`。

太好了这就是 key 大人。这和我们先前注意到的结果一致。

#### Vigenere 解密

使用标准 Vigenere 解密，将密钥 `LOSTDREAM` 循环使用，并将非字母符号在加密过程中丢弃，最后原样保留。

得到

```plain
flag{yu@nshen_qidong!}
```

**原神启动！**

### 02. Hidden Key

#### 初步分析

源码给了密文和泄露值: 

```py
# [140, 96, 112, 178, 38, 180, 158, 240, 179, 202, 251, 138, 188, 185, 23, 67, 163, 22, 150, 18, 143, 212, 93, 87, 209, 139, 92, 252, 55, 137, 6, 231, 105, 12, 65, 59, 223, 25, 179, 101, 19, 215]
# 2669175714787937
```

注意到 L17 将 `key` 按大端序解释为整数，右移 12 位后打印，高 52 位已经清晰可见。这样 64 位密钥只剩 12 位未知。也就是只需要枚举

$$
2^{12}=4096
$$

个候选密钥。

#### 枚举

具体流程如下：

1. 令 `low` 遍历 `0..4095`，拼接得到完整 64 位候选密钥。
2. 计算候选 key 的 MD5 整数种子。
3. 按原题调用顺序生成密钥流，并逐项异或解密。
4. 筛选全部为可打印 ASCII、以 `flag{` 开头且以 `}` 结尾的候选。
5. 使用找到的 key 重新生成完整密文，逐项与附件中的 42 个整数比较。
6. 再检查恢复 key 右移 12 位后的结果等于原题泄露值。

脚本见 [hidden_key_solve.py](/assets/hidden_key_solve.py)

得到密钥：

```text
key，十六进制：97b99e652b261b77
低 12 位：0xb77
```

以及 Flag:

```plain
flag{e319a58c-4dd6-4e6a-a3fb-f4b0d339faba}
```

###  03. Rosita

