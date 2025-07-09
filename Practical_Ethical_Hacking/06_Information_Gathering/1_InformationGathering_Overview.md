# Information Gathering (Reconnaissance)



## Passive Reconnaissance Overview

**Physical/Social Reconnaissance:**
(only rarely covered in the PEH course)

* Location information, e.g. satellite images, drone recon, building layout
  (e.g. break areas, badge readers, security, fencing)
* Job information, e.g. employees' names, job titles, phone numbers, etc. and
  pictures, e.g. badge/desk/computer photos

  **Web/Host Assessment**:
(will be done a lot in the PEH course)

* Target validation: Always verify that the IP range is correct! (Darknet Diaries
podcast with Rob Fuller/Mubix); tools: WHOIS, nslookup, dnsrecon
* Finding subdomains (especially in web pentesting): tools: Google Fu, dig,
Nmap, Sublist3r, Bluto, crt.sh, etc.
* Fingerprinting: Which services are running on a server or website? Which
  ports are open? Tools: Nmap, Wappalyzer, WhatWeb, BuiltWith, NetCat. Passive
  Recon: without touching/scanning any host, just use information that is
  already out on the internet.
* Data breaches: utilization of previously leaked access credentials; by far the
most common way to get into networks in external assessments.

Simply scanning a network to find a vulnerable service to get access will
nowadays usually not work any more, therefore information gathering and
enumeration is the most important step by far!



## Identifying Our Target

As the first step, we need to establish a client to attack using a public Bug
Bounty program, [bugcrowd.com](https://www.bugcrowd.com). On their website,
there is a list of hundrets of organizations that allow one to hack their website
and potentially get money for one's findings.

**Important:** Double-check that the organization still offers the respective
program and stay within scope of the program! Read the rules of engagement!
Avoid the targets listed under "Out of Scope"!

Example used in the course: tesla.com



Recommended multiple times on reddit as a good source for free bug bounty training:
[Portswigger Academy](https://portswigger.net/web-security)
