---
title: "247CTF - Compare the pair [ WEB ]"
date: 2022-02-27T18:33:12-05:00
draft: false
---

# Compare The Pair

## Description

Can you identify a way to bypass our login logic? MD5 is supposed to be a one-way function right?

## Solution

We are given the following php code.

```php
<?php
  require_once('flag.php');
  $password_hash = "0e902564435691274142490923013038";
  $salt = "f789bbc328a3d1a3";
  if(isset($_GET['password']) && md5($salt . $_GET['password']) == $password_hash){
    echo $flag;
  }
  echo highlight_file(__FILE__, true);
?>
```

PHP has a feature called `type juggling` or `type coercion`. This means that during the comparison of variables of different types, PHP will first convert them to a common, comparable type. Let's see the relevance of this in our code.

Note that the variable `password_hash` starts with 0e and everything else is numbers (php magic hashes) so it is considered as a float. 

```php
$password_hash = "0e902564435691274142490923013038";
```

If we continue reading the code, we will notice that a loose comparison is being made:

```php
isset($_GET['password']) && md5($salt . $_GET['password']) == $password_hash
```

Let's see what this type of comparison is about according to https://techgeekgalaxy.com/.

```
In PHP, variables of different data types can be compared using the loose comparison operator which is two equal signs (==). If two operands of different types are compared using loose comparison then there is an attempt to convert one or both of the operands and then compare them. The result of the conditional after conversion of an operand can sometimes lead to bugs or security exploits.
```

Once we have understood what it is all about, let's move on to the exploitation phase. The goal is quite simple, find a string that when mixed with the salt creates an MD5 hash starting with 0e and all other digits.

```php
<?php
$salt = "f789bbc328a3d1a3";
$x = 1;
while (True){
    if (md5($salt . $x) == 0){
        echo $x;
        $x++;
    } else{
        $x++;
    }
}
?>
```

The only thing missing would be to enter and pass the output to the password parameter.

```
https://76df5ddee940a4a1.247ctf.com/?password=<Output>
```

# Flag Authoriser

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