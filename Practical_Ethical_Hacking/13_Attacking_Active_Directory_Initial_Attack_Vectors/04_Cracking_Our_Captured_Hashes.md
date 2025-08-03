# Cracking Our Captured Hashes

We have copied one of the captured NTLMv2 hashes, including user and domain
name that precede the actual hash, and stored it in a file called `hashes.txt`.

We will use a tool called `hashcat`, which TCM prefers over the alternative in
Kali Linux, John the Ripper (`john`). Hash cracking on a virtual machine is
going to be incredibly slow and is therefore a no-no since we are running the
cracking software on the CPU in the virtual machine, whereas it can otherwise
run on the much faster GPU. Organizations that engage in pentesting oftentimes
have a *cracking rig* which has several GPUs installed and is solely used to
crack password hashes. There are also cloud-based services available, too. In
general, one should always run hash cracking on bare metal. I have installed
hashcat on my host machine to check how fast it runs there.

To find the relevant modules for `NTLM` protocol family we can invoke

```
$ hashcat -h | grep NTLM
   5500 | NetNTLMv1 / NetNTLMv1+ESS                                  | Network Protocol
  27000 | NetNTLMv1 / NetNTLMv1+ESS (NT)                             | Network Protocol
   5600 | NetNTLMv2                                                  | Network Protocol
  27100 | NetNTLMv2 (NT)                                             | Network Protocol
   1000 | NTLM                                                       | Operating System
```

We need to use module 5600 since we have captured an NTLMv2 hash. We can also
find the information online along with example hashes:
[hashcat wiki](https://hashcat.net/wiki/doku.php?id=example_hashes)



```
$ time hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-haswell-AMD Ryzen 7 PRO 4750U with Radeon Graphics, 14599/29262 MB (4096 MB allocatable), 16MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 4 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344391
* Bytes.....: 139921497
* Keyspace..: 14344384
* Runtime...: 0 secs

FCASTLE::MARVEL:ce342e09818e45dd:c72d9b8b06674079369d4da1611ff472:01010000000000008034a0e90f01dc012f8c600b46e06f72000000000200080056004b004e00340001001e00570049004e002d0047005a0033004b00570048003800360043005900490004003400570049004e002d0047005a0033004b0057004800380036004300590049002e0056004b004e0034002e004c004f00430041004c000300140056004b004e0034002e004c004f00430041004c000500140056004b004e0034002e004c004f00430041004c00070008008034a0e90f01dc01060004000200000008003000300000000000000001000000002000004f03e308f51acbff1d02bbb0bfa614fb8c46c6b35c1f7b9181731e0ef4368bf60a0010000000000000000000000000000000000009001a0063006900660073002f00310030002e0030002e0032002e0035000000000000000000:Password1
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: FCASTLE::MARVEL:ce342e09818e45dd:c72d9b8b0667407936...000000
Time.Started.....: Wed Jul 30 12:02:39 2025 (0 secs)
Time.Estimated...: Wed Jul 30 12:02:39 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   237.7 kH/s (3.21ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 16384/14344384 (0.11%)
Rejected.........: 0/16384 (0.00%)
Restore.Point....: 0/14344384 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> christal
Hardware.Mon.#1..: Temp: 81c Util:  8%

Started: Wed Jul 30 12:02:06 2025
Stopped: Wed Jul 30 12:02:40 2025

real	0m33,593s
user	0m32,005s
sys	0m0,913s
```



Runtime on the host operating system: 32 s. Same on the virtual machine: 30 s!
Surprising... The password was retrieved correctly: **Password1**

If a hash has already been cracked, the result will be stored in a *potfile*
that grows over time. We can show the results that have been found so far by
appending `--show` to the `hashcat` command used above. Password hashes that
have been cracked before will then not be cracked again. The difference between
NTLMv1 and NTLMv2 is that the hash changes every time we capture it if it is v2,
whereas v1 does not change.

```
$ hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt --show
FCASTLE::MARVEL:ce342e09818e45dd:c72d9b8b06674079369d4da1611ff472:01010000000000008034a0e90f01dc012f8c600b46e06f72000000000200080056004b004e00340001001e00570049004e002d0047005a0033004b00570048003800360043005900490004003400570049004e002d0047005a0033004b0057004800380036004300590049002e0056004b004e0034002e004c004f00430041004c000300140056004b004e0034002e004c004f00430041004c000500140056004b004e0034002e004c004f00430041004c00070008008034a0e90f01dc01060004000200000008003000300000000000000001000000002000004f03e308f51acbff1d02bbb0bfa614fb8c46c6b35c1f7b9181731e0ef4368bf60a0010000000000000000000000000000000000009001a0063006900660073002f00310030002e0030002e0032002e0035000000000000000000:Password1
```



Adding the flag `-O` for "optimized" is recommended to use settings that are
optimized for highest cracking speed on the available hardware. There is also a
newer password list called `rockyou2021` that has a size of 91 GB as opposed to
600 MB of the original `rockyou` wordlist:
[github repo](https://github.com/ohmybahgosh/RockYou2021.txt).

The password list can also be modified using *rules*, which are not covered in
more depth here. There is a famous combination of rules that improves the success
rate of cracking: [github repo](https://github.com/NotSoSecure/password_cracking_rules)
and an explanation for the approach:
[One Rule to Rule Them All](https://notsosecure.com/one-rule-to-rule-them-all)

**Application:**
`$ hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt -r
OneRuleToRuleThemAll.rule`

**For this course** and usually also for CTFs, the original `rockyou` list will
be a good starting point without using any additional rules, but for real world
password cracking, we will have to look for better wordlists and for rules that
are adapted to the situation in question, e.g. making use of knowledge about
the location of the attack victim, such as sports clubs, the company name or
names of family members.

The baseline for future password cracking attempts should be the command above,
including the `-O` switch, and we should study hashcat rules in addition to the
course material.



<!--
span style="color:green;font-weight:700;font-size:20px">
markdown color font styles
</span
-->
