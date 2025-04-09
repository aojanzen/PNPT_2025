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


