---
title: 'Cascading the Seven Seas'
description: 'Extracting memory from a CSS VM and reverse-engineering'
pubDate: '2026-04-05'
ctf: 'RITSEC CTF 2026'
category: 'web'
---

**RITSEC CTF 2026**

**Challenge:** Cascading the Seven Seas

**Category:** Web

**Flag:** `RS{CR3D1T_T0_LYR4_R3B4N3_F1BDF5}`

I participated in this CTF with my club team, tjcsc.

We are given only a link, `https://css.ctf.ritsec.club/`.

Going to this link reveals a page with an onscreen keyboard and three questions, the first asking what the biggest ocean is. Answering correctly with `PACIFIC` continues the quiz with asking what the biggest aquatic animal is. Answering `WHALE` is incorrect, however.

Let's get the source code for now: <br>
`curl -s https://css.ctf.ritsec.club/ -o whatever.html`

The HTML file is 723 kB? That's odd. Looking through it, we can see css @function tags defining functions for bitwise operations, memory access, and even an instruction decoder that maps to x86.

This is an x86-16 emulator built entirely with CSS. Cool.

Let's try extracting the ROM with regex:
```
import re

with open('whatever.html', 'r') as f:
    content = f.read()

pattern = r'@property\s+--m(\d+)\s*\{\s*syntax:\s*"<integer>";\s*initial-value:\s*(-?\d+);\s*inherits:\s*true;\s*\}'
mem = {int(a): int(v) & 0xFF for a, v in re.findall(pattern, content)}

with open('program.bin', 'wb') as f:
    for i in range(max(mem.keys()) + 1):
        f.write(bytes([mem.get(i, 0)]))
```

That works! Let's take a look...

The first few bytes are `CC 90 90 90...` up until offset `0x100`. After doing some research, I figured out that this is the layout of a COM program.

Let's disassemble with this command: <br>
`ndisasm -b 16 -o 0x100 -e 0x100 program.bin`

That works too, produces a x86-16 assembly with 5 functions: print_string, read_input, print_number, check, and main.

The main function does the following:
Prints welcome, prints Q1, read input into buffer at 0x5B0, check length == 7, then check(buf, 0x470, 10). If pass, print Q2, read input, check length == 5, then check(buf, 0x420, 10). If pass, print Q3, check length == 32, then check(buf,0x320, 32). If pass, you win. else, incorrect.

Q1 is asking what the biggest ocean is. Q2 is asking what the biggest aquatic animal is. Q3 is asking what the flag is. We can assume that the answer to Q3 is the flag.

The check function iterates over a table of 8-byte entries, each containing three byte indices and an expected value. 

Here's the essence of it:
```
mov bx, [entry+2]
mov al, [bx+di]
cbw
xchg ax, dx

mov bx, [entry+4]
mov al, [bx+di]
cbw
add dx, ax

mov bx, [entry+0]
mov al, [bx+di]
cbw
xor dx, ax

cmp dx, [entry+6]
```

Basically, the constraint per entry is that `(input[b] + input[c]) XOR input[a]` must equal an expected value. If any entry fails, return 1. If they all pass, return 0.

We've already solved Q1 with `PACIFIC`. Q2 is only 5 characters, so we can brute force it, yielding `HORSE` for some reason.

Now, Q3, the flag, is 32 characters. With 39 characters on the on-screen keyboard, we <s> are NOT brute forcing ts respectfully 😭✌️</s> have to use z3.

Let's think about our constraints.
- The flag format, of course; it must start with `RS{` and end with `}`.
- The onscreen keyboard; the flag may only contain the following characters: `0123456789QWERTYUIOPASDFGHJKL{_ZXCVBNM}`.
- The constraint in the check function: `(input[b] + input[c]) XOR input[a] == expected`.

We can get the expected values from the check table in the binary at offset 0x320. Here they are:
```
constraints_data = [
    (18, 12, 25, 247), (5, 11, 0, 177), (14, 20, 28, 223), (6, 23, 12, 214),
    (28, 3, 15, 209), (2, 1, 4, 222), (14, 27, 3, 220), (1, 24, 19, 193),
    (29, 7, 22, 57), (8, 9, 6, 247), ( 6, 27, 30, 51), (18, 10, 6, 202),
    (10, 28, 3, 211), (16, 21, 26, 81), (12, 20, 24, 254), (11, 10, 4, 150),
    (13, 28, 17, 239), (2, 15, 12, 202), (12, 19, 18, 218), (4, 27, 30, 37),
    (6, 17, 26, 212), (17, 14, 16, 210), (31, 27, 17, 220), (31, 18, 29, 229),
    (13, 25, 7, 59), (28, 18, 10, 226), (31, 30, 8, 244), (7, 5, 9, 163),
    (16, 28, 30, 77), (27, 12, 6, 225), (5, 27, 28, 181), (31, 18, 10, 219),
]
```

Let's put that all together in a z3 solver!
```
from z3 import *

constraints_data = [
    (18, 12, 25, 247), (5, 11, 0, 177), (14, 20, 28, 223), (6, 23, 12, 214),
    (28, 3, 15, 209), (2, 1, 4, 222), (14, 27, 3, 220), (1, 24, 19, 193),
    (29, 7, 22, 57), (8, 9, 6, 247), ( 6, 27, 30, 51), (18, 10, 6, 202),
    (10, 28, 3, 211), (16, 21, 26, 81), (12, 20, 24, 254), (11, 10, 4, 150),
    (13, 28, 17, 239), (2, 15, 12, 202), (12, 19, 18, 218), (4, 27, 30, 37),
    (6, 17, 26, 212), (17, 14, 16, 210), (31, 27, 17, 220), (31, 18, 29, 229),
    (13, 25, 7, 59), (28, 18, 10, 226), (31, 30, 8, 244), (7, 5, 9, 163),
    (16, 28, 30, 77), (27, 12, 6, 225), (5, 27, 28, 181), (31, 18, 10, 219),
]

charset_ords = [ord(c) for c in "0123456789QWERTYUIOPASDFGHJKL{_ZXCVBNM}"]

s = Solver()
chars = [BitVec(f'c{i}', 16) for i in range(32)]

s.add(chars[0] == ord('R'))
s.add(chars[1] == ord('S'))
s.add(chars[2] == ord('{'))
s.add(chars[31] == ord('}'))

for i in range(32):
    s.add(Or([chars[i] == v for v in charset_ords]))

for a, b, c, exp in constraints_data:
    s.add((chars[b] + chars[c]) ^ chars[a] == exp)

if s.check() == sat:
    m = s.model()
    print(''.join(chr(m[chars[i]].as_long()) for i in range(32)))
```

Running this prints the flag: 
`RS{CR3D1T_T0_LYR4_R3B4N3_F1BDF5}`

Overall, this was a creative web challenge. I had fun working through it.