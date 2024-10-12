---
title: Two Million
published: 2023-08-20
description: 'An in-detail writeup on how I pwned: Two Million box'
image: './TwoMillion.png'
tags: [hackthebox, linux, easy, revshells, kernel-exploit, privilege-escalation]
category: 'HackTheBox'
draft: false 
---


# TwoMillion

## Port Scans

```
Open 10.10.11.221:22
Open 10.10.11.221:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -sC" on ip 10.10.11.221
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.80 ( https://nmap.org ) at 2023-10-05 04:02 UTC
Scanning 10.10.11.221 (10.10.11.221) [2 ports]
Discovered open port 22/tcp on 10.10.11.221 
Discovered open port 80/tcp on 10.10.11.221 

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://2million.htb/ 
``` 

* Open ports `22` - ssh / `80` - http 


## Dirsearch Results

```bash
❯ dirsearch -u http://2million.htb/ -w /opt/wordlists/web/seclists-big.txt

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 20476

Output File: /home/trevohack/.dirsearch/reports/2million.htb/-_23-10-05_10-43-05.txt

Error Log: /home/trevohack/.dirsearch/logs/errors-23-10-05_10-43-05.log

Target: http://2million.htb/

[10:43:06] Starting: 
[10:43:13] 200 -    2KB - /404
[10:43:26] 401 -    0B  - /api
[10:43:28] 301 -  162B  - /assets  ->  http://2million.htb/assets/
[10:43:49] 301 -  162B  - /controllers  ->  http://2million.htb/controllers/
[10:43:51] 301 -  162B  - /css  ->  http://2million.htb/css/
[10:44:12] 301 -  162B  - /fonts  ->  http://2million.htb/fonts/
[10:44:22] 302 -    0B  - /home  ->  /
[10:44:27] 301 -  162B  - /images  ->  http://2million.htb/images/
[10:44:31] 200 -    4KB - /invite
[10:44:35] 301 -  162B  - /js  ->  http://2million.htb/js/
[10:44:43] 200 -    4KB - /login
[10:44:43] 302 -    0B  - /logout  ->  /
[10:45:31] 200 -    4KB - /register
[10:46:38] 301 -  162B  - /views  ->  http://2million.htb/views/
```

## Web Enumeration

![website](https://i.postimg.cc/t49nCmLC/htb-2million.png)

* Browsing to `/invite` may reveal a page asking for an invite code. 

* On the site, `inviteapi.min.js` loads everytime we reload the page. 

* Beatifying the javascript code may give an output like this:

```js
function verifyInviteCode(code) {
    var formData = {
        "code": code
    };
    $.ajax({
        type: "POST",
        dataType: "json",
        data: formData,
        url: '/api/v1/invite/verify',
        success: function(response) {
            console.log(response)
        },
        error: function(response) {
            console.log(response)
        }
    })
}

function makeInviteCode() {
    $.ajax({
        type: "POST",
        dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function(response) {
            console.log(response)
        },
        error: function(response) {
            console.log(response)
        }
    })
}
``` 

* Running the function `makeInviteCode()` on the console or doing a curl request may reveal the following.

![invitecode](https://i.postimg.cc/P5KpLQjb/invitecode.png)

* Decrypting the found rot13 cipher shows us this

```text
In order to generate the invite code, make a POST request to /api/v1/invite/generate
 ```

* Making a POST request to the given web path gives us a code 

```bash
❯ curl -X POST 2million.htb/api/v1/invite/generate
{"0":200,"success":1,"data":{"code":"Q1BFRk0tN1YwWDYtM1M0QTMtUDBXMjE=","format":"encoded"}}
``` 

* Decoding the it would give us a code `CPEFM-7V0X6-3S4A3-P0W21`

* Later on, we could head on to the website and make a user. 

![registration](https://i.postimg.cc/RFJNDrnG/registration.png)

* After, registration you will be redirected to `http://2million.htb/home`

![home-page](https://i.postimg.cc/hPBfp54b/home.png)

## Initial Access 

```bash
❯ curl -X GET \
  'http://2million.htb/api/v1' \
  -H 'Host: 2million.htb' \
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0' \
  -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' \
  -H 'Accept-Language: en-US,en;q=0.5' \
  -H 'Accept-Encoding: gzip, deflate, br' \
  -H 'Connection: close' \
  -H 'Cookie: PHPSESSID=ro74tjef9ne0g091ppuf8vjslp' \
  -H 'Upgrade-Insecure-Requests: 1' | jq .
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   800    0   800    0     0   1336      0 --:--:-- --:--:-- --:--:--  1337
{
  "v1": {
    "user": {
      "GET": {
        "/api/v1": "Route List",
        "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
        "/api/v1/invite/generate": "Generate invite code",
        "/api/v1/invite/verify": "Verify invite code",
        "/api/v1/user/auth": "Check if user is authenticated",
        "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
        "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
        "/api/v1/user/vpn/download": "Download OVPN file"
      },
      "POST": {
        "/api/v1/user/register": "Register a new user",
        "/api/v1/user/login": "Login with existing user"
      }
    },
    "admin": {
      "GET": {
        "/api/v1/admin/auth": "Check if user is admin"
      },
      "POST": {
        "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
      },
      "PUT": {
        "/api/v1/admin/settings/update": "Update user settings"
      }
    }
  }
}
```  

* Exploring the site, I found out something really interesting

![burp1](https://i.postimg.cc/NF1LQ1DH/burp1.png)

* Later on, I found a bind shell on `/api/v1/admin/vpn/generate`

![burp2](https://i.postimg.cc/mkxtxdY4/burp2.png)

## Privilege Escalation

* After, getting a shell on the `.env` variable reveals a password `SuperDuperPass12` for user `admin`.

* Logging in via ssh

```bash
❯ sshpass -p 'SuperDuperPass123' ssh -o StrictHostKeyChecking=no admin@$VMIP 
``` 

* After, some time looking through suids, linpeas I ran `uname -a` which reveal kernel info where I found an exploit for it later on.

* [Exploit](https://github.com/sxlmnwb/CVE-2023-0386)

![root](https://i.postimg.cc/VsMJ98wk/root.png)

## Rooted! 
