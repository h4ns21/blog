---
title: "247CTF - Tips and tricks [ WEB ]"
date: 2022-03-01T16:40:06-05:00
draft: false
---

When activating the challenge we are given a server which when we connect asks us to make a script to make the sum of the two random numbers that we are given and repeat this process 500 times.

![image](https://user-images.githubusercontent.com/88755387/156254205-4ada91d7-9fb8-4482-9aa5-5bba7b6a075e.png)

The first contact I had with the challenge was with the `socket` library. I thought it could be done with this library but I got to a point where I didn't know how to proceed. 

I leave the code below in case you want to take a look at it.



```python
#!/usr/bin/env python3
import socket

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('791c19ccdd996b1d.247ctf.com', 50459))

from_server = client.recv(1024)

# We create the first list and take out the first number

empty = []
for i in from_server.split():
    if i.isdigit():
        empty.append(int(i))
empty.remove(500)

# Second number is out

if (b' ' in from_server[-6:-5]) == True:
    empty.append(int(from_server[-5:-4]))
    empty.append(int(from_server[-4:-3]))
else:
    empty.append(int(from_server[-6:-5]))
    empty.append(int(from_server[-5:-4]))
    empty.append(int(from_server[-4:-3]))

# print(empty)

if (not b' ' in from_server[-6:-5] and not b'+' in from_server[-6:-5]) == True:
    y = ''.join(str(e) for e in empty[-3:])
    # print(y)
else:
    y = ''.join(str(e) for e in empty[-2:])
    # print(y)

# We create the second list

strings = [str(integer) for integer in empty[:1]]
a_string = "". join(strings)
an_integer = int(a_string)
# print(an_integer)

emptyv2 = []
emptyv2.append(an_integer)
emptyv2.append(int(y))
# print(emptyv2)

result = sum(emptyv2)

i = 0
while True:
     client.send(result)  # --> Here is the mistake
     i += 1
     if i == 500:
         break

client.close()

print(sum(emptyv2))
print(from_server)
```

When sending the result of the sum of the two numbers I didn't know how to do it in `int` format because I always got the same error.

![image](https://user-images.githubusercontent.com/88755387/156255164-b610c75c-0563-4a34-b4b0-a614a8304f24.png)

So I decided to do it with the pwntools library.

```bash
python3 -m pip install --upgrade pwntools
```

```python
#!/usr/bin/env python3
import socket
from pwn import *

r = remote('cd7f0d76ebed534c.247ctf.com', 50251)

# b'Welcome to the 247CTF addition verifier!\r\n'
print(r.recvline())
# b'If you can solve 500 addition problems, we will give you a flag!\r\n'
print(r.recvline())

for i in range(500):

        suma = r.recvline().decode("utf-8") # What is the answer to 1 + 2?

        # print(suma)

        split = suma.split() # ['What', 'is', 'the', 'answer', 'to', '1', '+', '2?']

        fn = int(split[5])            # '1' -> 1
        sn = int(split[7].strip('?')) # '2?' -> 2
    
        result = (str(fn + sn)+'\r\n').encode("utf-8")

        # print(result)

        r.sendline(result)

        r.recvline()

flag = r.recvline().decode("utf-8").strip('\r\n')

print("[+] The flag is:",flag)

r.close()
```

![image](https://user-images.githubusercontent.com/88755387/156256174-d7edb09d-3b74-47cd-ac30-31f62c790953.png)

I hope you liked! :D


