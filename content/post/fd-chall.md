---
title: "Fd pwnable.kr [ PWN ]"
date: 2022-02-27T18:44:48-05:00
draft: false
---

The first thing we have to do when logging into the ssh server is to look at the program code.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
        if(argc<2){
                printf("pass argv[1] a number\n");
                return 0;
        }
        int fd = atoi( argv[1] ) - 0x1234;
        int len = 0;
        len = read(fd, buf, 32);
        if(!strcmp("LETMEWIN\n", buf)){
                printf("good job :)\n");
                system("/bin/cat flag");
                exit(0);
        }
        printf("learn about Linux file IO\n");
        return 0;
}
```

### __Program analysis__

```python
int fd = atoi( argv[1] ) - 0x1234;
```

Atoi converts a string to an integer. Then, we subtract 0x1234, and assign that to the variable “fd”.

Then, we see:

```python
len = read(fd, buf, 32)
```

If we see the read man page:

```
ssize_t read(int fd, void *buf, size_t count);

read() attempts to read up to count bytes from file descriptor fd into the buffer starting at buf.
```

The count (32) and buffer are already set for us. If we can pass the string compare (strcmp) check, the program will read the flag file for us:

```python
if(!strcmp("LETMEWIN\n", buf)) {
    printf("good job :)\n");
    system("/bin/cat flag");
    exit(0);
}
```

### __To recap__

Pass in a number that, when we subtract 0x1234 from it, reads from a file and copies the string `LETMEWIN\n` into the buffer. On Linux, file descriptor 0 is standard input, so if we can set the file descriptor to 0, we can type in our LETMEWIN\n string.

0x1234 is hex notation… we need decimal. A quick Google search will get you `4660` as the decimal equivalent of 0x1234.  We can pass that to fd (the program), which will set fd (the variable) to zero, and let us type in the magic phrase.

```
fd@pwnable:~$ ./fd 4660
```

…which gives me a blank line. I then type (and hit return after):

```
LETMEWIN
```

And it prints out:

```
good job :)
mommy! I think I know what a file descriptor is!!
```