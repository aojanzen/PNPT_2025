# Passback Attacks

There is no lab for **Passback Attacks**. See the article below for an overview
how to exploit, e.g. printers with default credentials.

The key point is apparently to change the IP address in the login screen from
the domain controller's IP address to one that we control and then to set up a
listener (e.g. `netcat` or `responder`) on the machine we control. The password
is sent over in clear text, i.e. irrespective of its complexity, we just get
the login credentials sent through the IP connection. This kind of attack is
sometimes the last resort if the Windows network is otherwise set up correctly.



#### Further reading

* [How to Hack Through a Pass-Back Attack: MFP Hacking Guide](https://www.mindpointgroup.com/blog/how-to-hack-through-a-pass-back-attack)



<!--
span style="color:green;font-weight:700;font-size:20px">
markdown color font styles
</span
-->
