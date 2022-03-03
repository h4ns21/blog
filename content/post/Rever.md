---
title: "247CTF - Challenges [ REVERSING ]"
date: 2022-02-28T15:23:29-05:00
draft: false
---

In this post I will show the solution to the easiest challenges in the Reversing category.

## __THE MORE THE MERRIER [ EASY ]__

![image](https://user-images.githubusercontent.com/88755387/156053671-4bb25f34-3f03-4ec0-b54a-a356cde535d8.png)

When opening the main code in the IDA tool we notice that there is a weird variable called `unk_6E8` which is moving its content to the rax register.

![image](https://user-images.githubusercontent.com/88755387/156054315-fbe42ef0-2129-40f4-92fe-f53a9083eae2.png)

Let's see what's inside.

![image](https://user-images.githubusercontent.com/88755387/156055740-72794539-6db7-4e4a-ab02-49537b0d6ced.png)

We notice that it is the flag because of the first 4 characters `247{`. These are not shown if we launch the `strings` command because there are 3 bytes between each one.

## __The ENCRYPTED PASSWORD [ EASY ]__

This challenge is a little more complicated than the previous one but nothing that cannot be overcome.

![image](https://user-images.githubusercontent.com/88755387/156056808-72f45c8c-3e34-4b2e-a73d-c5c4062c8008.png)

Let's start the challenge by running it and see what it asks of us.

![image](https://user-images.githubusercontent.com/88755387/156058151-5861690d-2fe6-42b9-a5c3-83a9c44960e4.png)

We may think that entering the secret password will return the flag we are looking for. Let's open the program in Ghidra to analyze the main function.

![image](https://user-images.githubusercontent.com/88755387/156058929-f599dbf5-247b-4351-8f20-629610e724aa.png)

We can see that the variable `local_48` stores what we enter when we are asked for the password, so we are going to rename it as `user_input`.

```c
puts("Enter the secret password:");   
fgets(local_48,0x21,stdin);
```

If we continue reading we will realize that a comparison is made between what we have written and a variable called `local_78` which we do not know what it has inside.

```c
puts("Enter the secret password:");   
fgets(user_input,0x21,stdin);   
iVar2 = strcmp(user_input,(char *)&local_78);   
if (iVar2 == 0) {     
  printf("You found the flag!\n247CTF{%s}\n",&local_78);   
}
```

To better visualize this we will use the `ltrace` command which will help us to locate the content.

```bash
ltrace ./encrypted_password
```

![image](https://user-images.githubusercontent.com/88755387/156066637-c5f789b3-5dba-429b-b05c-265340b43031.png)

Once we know what you are comparing us to, we are going to throw the string at the program.

![image](https://user-images.githubusercontent.com/88755387/156066770-0107286d-d7fc-4f21-b77a-c8f6daea96a7.png)

This challenge can also be solved with the `Angr` tool, which is defined in the official [documentation](https://docs.angr.io/).

```
angr is a multi-architecture binary analysis toolkit, with the capability to perform dynamic symbolic execution (like Mayhem, KLEE, etc.) and various static analyses on binaries.
```
We are going to use the `.explore()` method with the `find` argument, this will cause the program to run until it finds a state with the search condition, in this case the word `found`.

```
An extremely common operation in symbolic execution is to find a state that reaches a certain address, while discarding all states that go through another address. Simulation manager has a shortcut for this pattern, the .explore() method.
```
Once we have understood how the tool works we are going to create a script to display the flag.

```python
import angr

proj = angr.Project('./encrypted_password')

simgr = proj.factory.simgr()

simgr.explore(find=lambda s: b"found" in s.posix.dumps(1))

s = simgr.found[0]
print(s.posix.dumps(1))
flag = s.posix.dumps(0)
print(flag)
```

![image](https://user-images.githubusercontent.com/88755387/156066898-14fa8fc0-43e3-4a3b-a838-53c38779eabb.png)

## __THE FLAG BOOTLOADER [ MODERATE ]__

![image](https://user-images.githubusercontent.com/88755387/156239595-60f7717d-2bb5-40cf-80bb-230a95df7f01.png)


When downloading the challenge file we will notice that it has a strange extension, so let's investigate to see what it is.

![image](https://user-images.githubusercontent.com/88755387/156219376-87513f98-ffff-46c7-aa9f-5ad55894f7ec.png)

A master boot record (MBR) is a special type of boot sector at the very beginning of partitioned computer mass storage devices like fixed disks or removable drives intended for use with IBM PC-compatible systems and beyond.

If we try to open this type of file with IDA it will not let us because we don't have the pro version installed so we will use the `ndisasm` command to see the assembly code.

```bash
ndisasm flag.com
```

Let's start the program from the value `0x7c00`, which is when the boot sector has been loaded into memory by the BIOS and control is passed to the boot sector.

```bash
ndisasm -o 7c00h flag.com > flag_offset.asm
```

We are reading the program little by little and we realize that there are several `jnz` jumps that are repeated, we are going to take the whole sequence and analyze it.

```asm
00007C7E  3004              xor [si],al
00007C80  46                inc si
00007C81  3004              xor [si],al
00007C83  43                inc bx
00007C84  46                inc si
00007C85  B053              mov al,0x53
00007C87  3406              xor al,0x6
00007C89  3807              cmp [bx],al
00007C8B  0F85ED00          jnz near 0x7d7c
```

What is happening here is the following:

It takes the character we input `al` and checks that this character when XORed with `0x6` is equal to `0x53`.

```
al XOR 0x6 ≠ 0x53  -->   ZF = 0  -->   jnz (jump if not zero)
al XOR 0x6 = 0x53  -->   ZF = 1  -->    / (no jump)
```

If this condition is false, it would jump to the specified address, which in this case is `0x7d7c`.

If we continue reading the code we are going to realize that there are 16 checks in total, therefore we are going to have to set 16 breakpoints and after each break we need to set the `ZF` flag to 1. The command we are going to use is the following.

```
set $eflags |= (1 << 6)  # ZF is the 6th bit of $eflags
```

Thanks to this [tutorial](https://rwmj.wordpress.com/2011/10/12/tip-debugging-the-early-boot-process-with-qemu-and-gdb/) we are going to attach the qemu tool with the gdb.

```bash
qemu-system-x86_64 -s -S -m 512 -fda flag.com
```

![image](https://user-images.githubusercontent.com/88755387/156226785-d82e4c7b-8c7b-446e-af2d-5977275f5786.png)

```
gdb-peda$ target remote localhost:1234
gdb-peda$ break * 0x7c00
gdb-peda$ c
```

![image](https://user-images.githubusercontent.com/88755387/156227136-5919e905-d2f4-4142-897b-f3b8a4ce90e5.png)

```
gdb-peda$ break * 0x7c7a
gdb-peda$ break * 0x7c8b
gdb-peda$ break * 0x7c9c
gdb-peda$ break * 0x7cad
gdb-peda$ break * 0x7cbe
gdb-peda$ break * 0x7ccf
gdb-peda$ break * 0x7ce0
gdb-peda$ break * 0x7cf1
gdb-peda$ break * 0x7d02
gdb-peda$ break * 0x7d11
gdb-peda$ break * 0x7d20
gdb-peda$ break * 0x7d2f
gdb-peda$ break * 0x7d3e
gdb-peda$ break * 0x7d4d
gdb-peda$ break * 0x7d5c
gdb-peda$ break * 0x7d6b
```

![image](https://user-images.githubusercontent.com/88755387/156228248-55f7b76d-b36c-4657-b147-7aba36cdf983.png)

```
gdb-peda$ set $eflags |= (1 << 6)  # --> ZF = 1
gdb-peda$ c
```

The last thing left to do is to open the qemu to show us what was hidden in it.

![image](https://user-images.githubusercontent.com/88755387/156228743-d0d6834c-e51a-4654-89a4-73e66fc85d40.png)

I hope you enjoyed it! :D