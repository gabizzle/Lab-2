# 📝 Active Information Gathering Report

## Summary

## Methodology

| Virtual Machine | Windows 7 | Kali Linux | Metasploitable 2 |
| ------------- | ------------- | ------------- | ------------- |
| IP Address | 192.168.56.101 | 192.168.56.102 | 192.168.56.103 |
| Subnet Mask | 255.255.255.0 | 255.255.255.0 | 255.255.255.0 |
| Default Gateway | 192.168.56.1 | 192.168.56.1 | 192.168.56.1 |

Firewalls are disabled,

### NMAP
To find which ports are active:
**nmap 192.168.56.0/24**
```
Starting Nmap 7.91 ( https://nmap.org ) at 2023-02-28 12:45 EST
Nmap scan report for 192.168.56.1
Host is up (0.00012s latency).

Nmap scan report for 192.168.56.101
Host is up (0.00017s latency).

Nmap scan report for 192.168.56.102
Host is up (0.00023s latency).

Nmap scan report for 192.168.56.103
Host is up (0.00018s latency).

Nmap scan report for 192.168.56.255
Host is up (0.0014s latency).

Nmap done: 256 IP addresses (5 hosts up) scanned in 1.26 seconds
```

To find which ports from 1-1000 are open:
**nmap -p 1-1000 192.168.56.101**
```
Starting Nmap 7.91 ( https://nmap.org ) at 2023-02-28 12:30 EST
Nmap scan report for 192.168.56.101
Host is up (0.00049s latency).

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3306/tcp open  mysql

Nmap done: 1 IP address (1 host up) scanned in 0.08 seconds
```

To know the OS running on the specific IP address:
**nmap -O 192.168.56.102**
```
Starting Nmap 7.91 ( https://nmap.org ) at 2023-02-28 12:55 EST
Nmap scan report for 192.168.56.102
Host is up (0.00050s latency).

Not shown: 999 filtered ports

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.88 seconds
```
To scan for vulnerabilities:
**nmap -sV --script vuln 192.168.56.103**
```
Starting Nmap 7.91 ( https://nmap.org ) at 2023-03-01 10:30 EST
Nmap scan report for 192.168.56.103
Host is up (0.00044s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| vuln: 
|   cve_2016_8858: 
|_    A remote code execution vulnerability exists in OpenSSH
111/tcp  open  rpcbind 2-4 (RPC #100000)
|_ vuln: 
|   CVE-2017-16995: 
|   | The NFSv2/NFSv3 server in the nfsd subsystem in the Linux kernel through 4.15. 
|   | allows remote attackers to cause a denial of service (system crash) 
|   | because a length field is not validated in XDR requests to 
|   | NFSv2/v3 write arguments, related to fs/nfsd/nfs3xdr.c and fs/nfsd/nfsxdr.c.
|   CVE-2018-16884: 
|   | In the Linux kernel 4.15.x through 4.19.x before 4.19.2, map_write() 
|   | in kernel/user_namespace.c allows privilege escalation 
|   | because it mishandles nested user namespaces with more than 5 UID or GID ranges.
|_  CVE-2018-16885: 
|   | The do_xfs_setattr function in fs/xfs/xfs_ioctl.c in the Linux kernel 
|   | through 4.19.6 allows local users to cause a denial of service 
|   | (memory corruption and system crash) or possibly have unspecified 
|   | other impact by changing a certain XFS disk layout. 
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
| vuln: 
|   CVE-2007-2446: 
|   | The SMB server in Samba 3.0.0 through 3.0.25rc3 allows remote attackers 
|   | to execute arbitrary commands via a crafted packet that triggers 
|   | a heap-based buffer overflow in the (1) Samba daemon 
|   | process or (2) nmbd process.
|_  CVE-2017-7494: 
|   | Samba before 4.4.14, 4.5.x before 4.5.10, and 4.6.x before 4.6.4 
|   | allows remote authenticated users to leverage access to an 
|   | SMB1 share to create a symlink file to any location on the 
|   | filesystem when the underlying filesystem does not support symlink creation, 
|   | and then manipulate the contents of a non-symlink file to create a 
|   | setuid binary file that results in elevated privileges for 
|   | a non-root user.
445/tcp  open  netbios-ssn Samba smbd 4.3
```



## Metasploitable 2 Findings & Recommendations
NetCat port scan on ports 1-1000:
**nc -zv 192.168.56.103 1-1000**
```
Connection to 192.168.56.103 21 port [tcp/ftp] succeeded!
Connection to 192.168.56.103 22 port [tcp/ssh] succeeded!
nc: connect to 192.168.56.103 port 23 (tcp) failed: Connection refused

Connection to 192.168.56.103 80 port [tcp/http] succeeded!
nc: connect to 192.168.56.103 port 139 (tcp) failed: Connection refused
nc: connect to 192.168.56.103 port 445 (tcp) failed: Connection refused
```



## Windows 7 Findings & Recommendations

## References
 
