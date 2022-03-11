---
title: "247CTF - Flag Authoriser [ WEB ]"
date: 2022-03-11T14:33:08-05:00
draft: false
---

## Description

Can you forge a new identity to upgrade your access from an anonymous user to an admin?

## Solution

We are given the following python code by clicking on the link provided.

```python
from flask import Flask, redirect, url_for, make_response, render_template, flash
from flask_jwt_extended import JWTManager, create_access_token, jwt_optional, get_jwt_identity
from secret import secret, admin_flag, jwt_secret

app = Flask(__name__)
cookie = "access_token_cookie"

app.config['SECRET_KEY'] = secret
app.config['JWT_SECRET_KEY'] = jwt_secret
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['DEBUG'] = False

jwt = JWTManager(app)

def redirect_to_flag(msg):
    flash('%s' % msg, 'danger')
    return redirect(url_for('flag', _external=True))

@jwt.expired_token_loader
def my_expired_token_callback():
    return redirect_to_flag('Token expired')

@jwt.invalid_token_loader
def my_invalid_token_callback(callback):
    return redirect_to_flag(callback)

@jwt_optional
def get_flag():
    if get_jwt_identity() == 'admin':
        return admin_flag

@app.route('/flag')
def flag():
    response = make_response(render_template('main.html', flag=get_flag()))
    response.set_cookie(cookie, create_access_token(identity='anonymous'))
    return response

@app.route('/')
def source():
    return "%s" % open(__file__).read()

if __name__ == "__main__":
    app.run()
```

When analyzing the code we see several things that catch our attention:

- There is a directory called `flag` to which we have access.
- A [JWT](https://jwt.io/introduction) (JSON Web Token) is being used. 

We are going to log in as the user `anonymous` to the main page but if we manage to change that identity field value to `admin` in the `/flag` directory we are going to get the flag. 

```python
@jwt_optional
def get_flag():
    if get_jwt_identity() == 'admin':
        return admin_flag
```

Once we have identified the most important parts of the code we will extract the cookie from the `/flag` directory to debugger it on this [page](https://jwt.io/).

![image](https://user-images.githubusercontent.com/88755387/157949706-63890623-11e0-4cec-bc73-a8bd48f37a52.png)

This is the part that we need to replace but there is one thing missing that is essential for this to work, we need to take out the signature that it has been encoded with. 

The signature is used to verify the message wasn't changed along the way, and, in the case of tokens signed with a private key, it can also verify that the sender of the JWT is who it says it is.

Therefore we will bruteforce it with the `john` tool.

![image](https://user-images.githubusercontent.com/88755387/157950921-59981354-693e-4606-86bb-79e82685e8e7.png)

Now that we have the key we are going to enter it in the signature field.

![image](https://user-images.githubusercontent.com/88755387/157951853-8ad7e2e2-0bdb-4122-a998-c238fc287c1c.png)

Before passing it to the web to see if it works, let's check if this is the key we are looking for. We are going to do this using an extension that BurpSuite has called `JSON Web Tokens`.

![image](https://user-images.githubusercontent.com/88755387/157952944-fdcc354e-a34b-4272-9bf5-7556eab87d90.png)

We see that the token has expired or is invalid, this does not mean that it is useless, simply that, because of the time that appears in the `exp` or `expiration time` field, it has expired for that session but we can create another one without needing to modify the value of this field.

It's time to send it the cookie to see if the page will return the flag.

![image](https://user-images.githubusercontent.com/88755387/157955409-4c28c963-8933-46be-bb42-de00389e2bdd.png)

I hope you enjoyed it! :D






