---
title: "247CTF Easy Challs [ Reversing ]"
date: 2022-02-28T15:23:29-05:00
draft: false
---

In this post I will show the solution to the easiest challenges in the Reversing category.

## __The More The Merrier__

![image](https://user-images.githubusercontent.com/88755387/156053671-4bb25f34-3f03-4ec0-b54a-a356cde535d8.png)

When opening the main code in the IDA tool we notice that there is a weird variable called `unk_6E8` which is moving its content to the rax register.

![image](https://user-images.githubusercontent.com/88755387/156054315-fbe42ef0-2129-40f4-92fe-f53a9083eae2.png)

Let's see what's inside.

![image](https://user-images.githubusercontent.com/88755387/156055740-72794539-6db7-4e4a-ab02-49537b0d6ced.png)

We notice that it is the flag because of the first 4 characters `247{`. These are not shown if we launch the `strings` command because there are 3 bytes between each one.

## __The Encrypted Password__

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

I hope you liked the writeups! :D