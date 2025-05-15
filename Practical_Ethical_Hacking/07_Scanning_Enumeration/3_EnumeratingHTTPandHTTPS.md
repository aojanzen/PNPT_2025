# Enumerating HTTP and HTTPS

Interesting open ports as points of attack from Kioptrix port scan:

* 80 and 443, HTTP and HTTPS
* 139, sometimes in combination with 445, SMB

SMB has been historically bad: WannaCry / EternalBlue, and websites, too. Port
22 (SSH) is less prone, e.g. through brute force attacks or stolen credentials
-- not common as attack target.

If there is a website (80, 443), try and go to the website first. The website
might give clues about the architecture on the target, e.g. the web server and
operating system, diligence (open ports for no reason?), version numbers, naming
conventions, etc.. *Make the findings part of the pentesting report!*



## Nikto

Nikto is a web vulnerability scanner that is particularly helpful for beginners
(Vulnhub, CTF, HackTheBox). If the website runs good security measures, the
Nikto scans might be blocked (oftentimes not the case!).

<img src="./nikto.png" alt="Nikto" width="800"/> 

`nikto -h http://10.0.2.4`

`-h` : specify host

Look for outdated software for a pentesting report, also the mentioned
vulnerabilities and exploits (here: mod_ssl vulnerable to remote buffer overflow).
Save the scan for later!


