---
title: Keeper  
published: 2023-10-03
description: "An in-detail writeup on the linux box: Keeper. From boot to root!"
image: "./Keeper.png"
tags: ["htb", "box", "easy", "linux", "reverse-shells", "privilege-escalation", "putty-rsa"]
category: HackTheBox
draft: false
---

# Keeper 

## Port Scan

```bash
Starting Nmap 7.80 ( https://nmap.org ) at 2023-10-07 13:05 +0530
Initiating Parallel DNS resolution of 1 host. at 13:05
Completed Parallel DNS resolution of 1 host. at 13:05, 0.08s elapsed
Initiating SYN Stealth Scan at 13:05
Scanning 10.10.11.227 [65535 ports]
Discovered open port 22/tcp on 10.10.11.227
Discovered open port 80/tcp on 10.10.11.227
Completed SYN Stealth Scan at 13:05, 12.96s elapsed (65535 total ports)
Nmap scan report for 10.10.11.227
Host is up, received user-set (0.66s latency).
Scanned at 2023-10-07 13:05:40 +0530 for 13s
Not shown: 39390 filtered ports, 26143 closed ports
Reason: 39390 no-responses and 26143 resets
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63 
80/tcp open  http    syn-ack ttl 63 
``` 

* Open ports: 80 http / 22 ssh

## Web Enumeration

![page](https://i.postimg.cc/90C7KLdS/keeper-page1.png)



* The website shows a link to `tickets.keeper.htb`, this should be added to your `/etc/hosts` along with `keeper.htb`

* After, that visiting the link directed me to a login page. 

![login-page](https://i.postimg.cc/MGYMR72m/login.png)

* As always, I tried bruteforcing and got the password, later I found out that they were the default creds of the service. `root:password`

* Once you login in, you'll be directed to a dashboard with `root` access. 

![home](https://i.postimg.cc/QtxbWNPV/home.png)

* Looking into the site I found something interesting under user `lnorgaard`

![lnorgaard](https://i.postimg.cc/Y9nxNKKR/inorgaard.png)

* As you can see we have found some creds `lnorgaard:Welcome2023!`, then I logged into the machine via ssh



```bash
❯ sshpass -p 'Welcome2023!' ssh -o StrictHostKeyChecking=no lnorgaard@$VMIP

``` 

* There you can read your user flag. 

* You will find an interesting ZIP file `RT30000.zip` which I transferred to my local machine via python3. 

* Afterwards, I read the `poc.py` file and got to know it's sorta a CVE. 

![db-pass](https://i.postimg.cc/TwJwLmFv/db-pass.png)

* Looking it on Google revealed this `Rødgrød med Fløde`

* I logged into the database with keepassxc, using the password `rødgrød med fløde`

* Next, I found a PuTTY RSA for root

![db](https://i.postimg.cc/Fzc7r8vG/db.png)

* I copied the text to a file and I converted the PuTTY privat key to the OpenSSH private key.

```bash
❯ puttygen putty_rsa -O private-openssh -o root_id_rsa
``` 

* Once, that is done I logged into to root via ssh `ssh -i root_id_rsa root@$VMIP`

* And you'll find the root flag there 

## PWNED! 
