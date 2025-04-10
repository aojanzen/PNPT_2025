# Setting Up Our Lab



## Installing VMWare / VirtualBox

A **Virtual Machine** is a machine inside a machine, e.g. Kali Linux, Windows,
etc. Running VMs can become reource-intensive. Recommended: 16 GB RAM for
Active Directory Lab. Running the pentesting operating system in a virtual
machine is common in the industry.

* [VMware](https://www.vmware.com/products/workstation-player/workstation-player-evaluation.html) -- VMWare workstation Pro (not Player) will be used by TCM in this course
* [VirtualBox](https://www.virtualbox.org/wiki/Downloads) -- free source and
  software, maintained by Oracle

## Configuring VirtualBox

* Recommended: Virtualbox Extension Pack, can be found with Google
* Installation: open Virtualbox, click Preferences, click Extensions, click "+"
  sign, chose downloaded file (extension pack)
* Under Virtualbox Preferences click Network, click "+" sign to add a "NatNetwork",
double-click, keep private network CIDR, and make sure DHCP support is active
* Make sure that every machine used in the course is set to "NAT Network / NatNetwork"
in VM settings so that all VMs are running on the same subnet

## Installing Kali Linux

* Debian-based geared towards hacking and penetration testing
* No/few downloads of hacking tools needed
* Download correct virtual machine version (Virtualbox / VMWare)
* Klicking on .vmx file will start the virtual machine under VMWare
* With 8 GB RAM installed, chose 1 GB or 2 GB RAM for the VM
* Make sure "Network adapter" is set to NAT (NatNetwork on Virtualbox) and DHCP
  is activated on all virtual machines, otherwise they do not see each other!
* Change password from `kali:kali` to a long, but easy to remember password.
* Add to `~/.profile`: `setxkbmap de -option caps:swapescape`

