# Introduction

**Scenario:** We are performing a pentest for a client. As part of the pentest
we are going to send a Laptop or Raspberry Pi to the customer. There is a VPN
installed on the Laptop or RPi that "phones home" (us), when plugged in so that
we can share the tunnel and can run an internal pentest without having to
travel to the customer. Pentests therefore usually do not have to be run on site.
We are assuming for the pentest that a machine has been compromised and an
attacker was able to get into the internal network.

The IP addresses in TCMs videos may change in this chapter. We have to keep an
eye on that issue. Besides our attack machine, we only need to know the IP
addresses of our domain controller and the two user machines:

* Domain controller `HYDRA-DC` (Windows Server 2022): `10.0.2.15`
* User machine `THEPUNISHER` (Windows 10 Enterprise): `10.0.2.6`
* User machine `SPIDERMAN` (Windows 10 Enterprise): `10.0.2.4`



<!--
span style="color:green;font-weight:700;font-size:20px">
markdown color font styles
</span
-->
