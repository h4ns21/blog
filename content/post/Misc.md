---
title: "247CTF - Challenges [ MISC ]"
date: 2022-03-03T13:28:36-05:00
draft: false
---

In this post I am going to show you how to perform some easy rating challenges on the [247CTF](https://247ctf.com/dashboard) platform.

## __An Impossible Number__

### __Description__

Can you think of a number which at the same time is one more than itself?

### __Solution__

We are given the following C code.

```c
#include <stdio.h>
int main() {
    int impossible_number;
    FILE *flag;
    char c;
    if (scanf("%d", &impossible_number)) {
        if (impossible_number > 0 && impossible_number > (impossible_number + 1)) {
            flag = fopen("flag.txt","r");
            while((c = getc(flag)) != EOF) {
                printf("%c",c);
            }
        }
    }
    return 0;
}
```

The first thing that comes to mind when thinking about this number is the so-called `integer overflow` attack. This attack occurs when adding 1 to the last positive number WITH SIGN becomes the first negative number. Let's look at an example.

```
7f ff ff ff [ HEX ] = 2147483647 [ DECIMAL ]

2147483647 + 1 = 80000000 (Maximum negative)
```

The following is proof that what I am telling you is true.

![image](https://user-images.githubusercontent.com/88755387/156632035-4175768b-3476-4bc2-a5fb-330b25cc42d2.png)

Therefore the previous number is the one we have to enter to show the flag.

![image](https://user-images.githubusercontent.com/88755387/156633679-43b37baa-1c30-4a4f-865b-8ce1f42bc96e.png)

## __The Flag Lottery__

### __Description__

Can you guess the secret number to win the lottery? The prize is a flag!

### __Solution__

We are given the following python code.

```python
import SocketServer, threading, random, time

class ThreadedLotteryServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

class LotteryHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        secret = random.Random()
        secret.seed(int(time.time()))
        winning_choice = str(secret.random())
        self.request.sendall("Can you guess the number to win the flag lottery?\n")
        your_choice = self.request.recv(1024).strip()
        if winning_choice == your_choice:
            self.request.sendall("Congratulations you won the lottery! Have a flag!\n")
            self.request.sendall("%s\n" % open('flag.txt').readline().rstrip())
        else:
            self.request.sendall("Nope! The winning number was %s, better luck next time!\n" % winning_choice)
        return

if __name__ == '__main__':
    SocketServer.TCPServer.allow_reuse_address = True
    server = ThreadedLotteryServer(("0.0.0.0", 5000), LotteryHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    server.serve_forever()
```

The function `time.time()` returns the current time as a floating point number and in this case the float is passed to an integer. We know that by doing this conversion, it is rounded down to the nearest whole number.

This results in up to 1s difference in which `random.seed` can receive the same seed (current time) therefore we can use as new input the previous winning number to enter it before that second passes.

We are going to create a script to automate this process.

```python
#!/usr/bin/env python3
from pwn import *

# Initial response
n = b'42'

while True:
    r = remote('a272c1f1d44392b4.247ctf.com', 50075) # tcp://a272c1f1d44392b4.247ctf.com:50075
    
    # Can you guess the number to win the flag lottery?
    r.recvline()

    # Send number (n)
    r.sendline(n)

    # Set response to current time
    n = r.recvline()
    n = n.split()[5][:-1]  # 0.811695956092 --> winner number
    print(n)

    # Print the flag if we recieve it
    if r.can_recv():
        print(r.recvline())
        break
```

![image](https://user-images.githubusercontent.com/88755387/156637228-927884d5-c5ad-4b24-b48b-53b0714acde9.png)

I hope you enjoyed it! :D















