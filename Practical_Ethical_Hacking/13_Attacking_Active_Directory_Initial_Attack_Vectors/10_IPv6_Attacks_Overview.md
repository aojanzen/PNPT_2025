# IPv6 Attacks Overview

**DNS takeover attacks via IPv6** are the current go-to attack for TCM. They
are another form of relay attacks, but much more reliable than SMB relay
attacks.

Machines on Windows networks usually run on IPv4, and there is a good chance
that the network is not utilizing IPv6 at all, even though IPv6 is probably
switched on. The question is: who is doing DNS for IPv6, and usually the answer
is: nobody! We can therefore just set up a fake DNS server for all IPv6
traffic. We can then get authentication to the domain controller either through
LDAP or SMB.

We will use a tool called `mitm6` (man-in-the-middle) in combination with
`ntlmrelayx`, which we have already used before. An event like a reboot allows
us to log in to the domain controller and retrieve a lot of information, even
if the account is not an admin. As an alternative, when someone logs in to the
domain or uses their credentials otherwise, the login credentials come through
to us via NTLM us like in an SMB relay, and we can do an **LDAP relay** to the
domain controller. If the used account is an admin, `mitm6` can create a new
account that we can use for further exploits. 



<!--
span style="color:green;font-weight:700;font-size:20px">
markdown color font styles
</span
-->
