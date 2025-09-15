# ***Zeek NIDS with OpenSSH Server - Network Intrusion Detection System(Integrating "Suricata" rules similar to "Snort" rules)***


> - In this tutorial we`ll be building a Home Lab, using Zeek NIDs + FileBeat Input Agent(Written in Golang Programming Language) + Connected to an output Elastic Search.Specifically our NIDS Server, will have "two" separate "interfaces", one of which will be connected to a "Private Network", whilst the other one will be connected to the "NIDS Management Network" where it will also be sending "Log information". 


> [!TIP]
> Remember : Our "Guest Machine" is a "Kali OS machine", and the default SSH Server that will be installed will be in the built-in "OpenSSH Server".


_Let's install the "OpenSSH Server" to begin with on the Kali Machine_: 

```
 $ sudo apt-get install  openssh-server

Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
openssh-server is already the newest version (1:9.2p1-2).
openssh-server set to manually installed.
The following packages were automatically installed and are no longer required:
  catfish dh-elpa-helper docutils-common gir1.2-xfconf-0 libcfitsio9 libgdal31 libmpdec3 libnginx-mod-http-geoip
  libnginx-mod-http-image-filter libnginx-mod-http-xslt-filter libnginx-mod-mail libnginx-mod-stream libnginx-mod-stream-geoip libpoppler123
  libprotobuf23 libpython3.10 libpython3.10-dev libpython3.10-minimal libpython3.10-stdlib libtiff5 libzxingcore1 nginx-common nginx-core
  python-pastedeploy-tpl python3-alabaster python3-commonmark python3-docutils python3-imagesize python3-roman python3-snowballstemmer
  python3-speaklater python3-sphinx python3.10 python3.10-dev python3.10-minimal ruby3.0 ruby3.0-dev ruby3.0-doc sphinx-common
Use 'sudo apt autoremove' to remove them.
0 upgraded, 0 newly installed, 0 to remove and 283 not upgraded.
```


> [!IMPORTANT]
> Importantly, the interface through which our "NIDS" would be connected, would not have any sort of liaison with it, in other words, this would not produce any "ARP" tables and neither any routing tables under the NIDS.


> [!CAUTION]
> For security reason : We do not want to alarm or tip off the attacker to our "Defense Mechanism" that has been put into place, hence this Network interface(contain no IP Address) will be divulging "Read-Only" information to our NIDS.




> [!NOTE]
> We are configuring two network interfaces inside our Kali Linux VM for use with Zeek:

> - eth0 – Bridged Adapter (used as a stealth sniffing interface, in promiscuous mode, no IP assigned)
> - eth2 – Host‑only Adapter (used for management and internet access if required; assigned an IP automatically or manually)



> _We require "Zeek" to listen to all "traffic on the bridged interface", hence we must enable promiscuous mode on the "interface eth0"_:         


````
┌──(root㉿kali)-[/home/kali]
                                                                                  
└─# sudo ip link set eth0  promisc on up
````

> [!IMPORTANT]
> eth0 (Bridged Adapter) 
> Understanding Interface roles and visibility

> - The eth0 (bridged) interface is used purely for passive monitoring.
> - It  performs no acive communication.
> - It does not generate ARP traffic or populate routing tables.
> - This ensures the interface remains invisible and non-interactive on the network, avoiding detection by an attacker.


> Assign a Static IP aadress to eth0 :  

```
┌──(osint㉿tlosint)-[~]

└─$ sudo ip addr add 192.168.2.80/24 dev eth0
```



> [!IMPORTANT]
> eth2 (Host-only Adapter)

> The eth2 interface uses VMware's host-only network. This allows communication between the guest VM and the host machine and this interface does have an IP address (e.g., 192.168.233.132)

> It can be used for management tasks like :

> - SSH access
> - File transfer
> - Package updates (if NAT is enabled on the host)






> [!NOTE]
> Since this setup operates over a wireless connection, the bridged adapter on the VM is connected to the wireless interface of the Windows host machine. The local network is configured within the 192.168.2.0/24 Class C private IP range, and the router's gateway address is typically 192.168.2.1.
Because the bridged adapter did not obtain an IP address dynamically via DHCP, we manually assigned a static IP address within the same subnet—specifically, 192.168.2.80 to ensure it falls within the valid IP range of the network. Alongside this, we also configured a default route pointing to the gateway at 192.168.2.1, allowing outbound traffic to be properly routed through the bridged interface.





> As a good practice before proceeding with this lab, ensure that you remove any existing or conflicting default routes prior to adding new ones:

```
┌──(osint㉿tlosint)-[~]

└─$ sudo ip route del default
```


> - _"Reset" the "interface" before "reassigning a new static IP address"_: 


```
┌──(osint㉿tlosint)-[~]

└─$ sudo ip addr flush dev eth2
```



> - _Let's add our default route for our bridge adapter_:

```
┌──(osint㉿tlosint)-[~]

└─$ sudo ip route add default via 192.168.2.1 dev eth0
```



> - _Verify our default route_: 

```
┌──(osint㉿tlosint)-[~]

└─$ ip route show

default via 192.168.2.1 dev eth0
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown
192.168.2.0/24 dev eth0 proto kernel scope link src 192.168.2.80
 ```



# ***Configuring the Open-SSH Server + Enable Root Login***
   

> - To summarize, our OpenSSH Server would need both an "id_rsa key" to allow for an "initial authentication with the Server" during the "3-way handshake mechanism", and still very much requires for an "ssh_host_* key" to encrypt the communication between both "client and server end". 


> [!TIP]
> _Ensure that OpenSSH-Server has been properly install and configured_: 

```
$ dpkg  -s  openssh-server
```

```
$ dpkg -l  | grep openssh-server
```




> [!TIP]
> _In order to access the "SSH Server", we would also need a "private key-pair", namely "sshd_config file" in the directory, "/etc/ssh"._ 


> _Let's verify if this is present_ :

```
┌──(root㉿kali)-[/home/kali]

└─# ls -larh /etc/ssh     


total 624K
-rw-r--r--   1 root root  563 Apr 21 15:35 ssh_host_rsa_key.pub
-rw-------   1 root root 2.6K Apr 21 15:35 ssh_host_rsa_key
-rw-r--r--   1 root root   91 Apr 21 15:35 ssh_host_ed25519_key.pub
-rw-------   1 root root  399 Apr 21 15:35 ssh_host_ed25519_key
-rw-r--r--   1 root root  171 Apr 21 15:35 ssh_host_ecdsa_key.pub
-rw-------   1 root root  505 Apr 21 15:35 ssh_host_ecdsa_key
-rw-r--r--   1 root root 1.0K Apr 30 22:58 .sshd_config.swp
drwxr-xr-x   2 root root 4.0K Oct 16  2022 sshd_config.d
```

> - _Great this is available !_

````
* ---> ----rw-r--r--   1 root root 3.2K Mar 25 14:37 sshd_config
````

````
drwxr-xr-x   2 root root 4.0K Oct 16  2022 ssh_config.d
-rw-r--r--   1 root root 1.7K Oct 16  2022 ssh_config
-rw-r--r--   1 root root 561K Feb  8 05:43 moduli
drwxr-xr-x 193 root root  12K Apr 30 22:48 ..
drwxr-xr-x   4 root root 4.0K Apr 30 22:58 .
````



> [!WARNING]
> _Important : Since we need to enable root login on the OpenSSH Server, however, this is only to be deployed on a development server, never on a production server._


> - Enable the ssh service : 


```
┌──(root㉿kali)-[~]

└─# systemctl enable ssh


Synchronizing state of ssh.service with SysV service script with /lib/systemd/systemd-sysv-install.
Executing: /lib/systemd/systemd-sysv-install enable ssh
Created symlink /etc/systemd/system/sshd.service → /lib/systemd/system/ssh.service.
Created symlink /etc/systemd/system/multi-user.target.wants/ssh.service → /lib/systemd/system/ssh.service.
```


> - Ensure that the root password has been set correctly, or try to set up a "new one" if needed :

```

$ sudo -i 

┏━(Message from Kali developers)
┃
┃ This is a minimal installation of Kali Linux, you likely
┃ want to install supplementary tools. Learn how:
┃ ⇒ https://www.kali.org/docs/troubleshooting/common-minimum-setup/
┃
┗━(Run: “touch ~/.hushlogin” to hide this message)

```

> - Modifying the password : 

```
$ passwd 
```

> - Edit the contents of sshd_config file using nano editor : 

```
$ nano /etc/ssh/sshd_config 
```


```
  GNU nano 7.2                                                  /etc/ssh/sshd_config                                                           

# This sshd was compiled with PATH=/usr/local/bin:/usr/bin:/bin:/usr/games

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

Include /etc/ssh/sshd_config.d/*.conf

# Port 22
# AddressFamily any
# ListenAddress 0.0.0.0
# ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
#LogLevel INFO
```


> [!IMPORTANT]
> We want to primarily tweak some of the options under "Authentication". 

> - #LoginGraceTime 2m
> - #PermitRootLogin prohibit-password
> - #StrictModes yes
> - #MaxAuthTries 6
> - #MaxSessions 10


> [!NOTE]
>  Ensure that these are confgiured as required : 

> - LoginGraceTime 2m
> - PermitRootLogin yes        # ← changed this from prohibit-password to yes
> - StrictModes yes
> - MaxAuthTries 6
> - MaxSessions 10


> _"Restart the "ssh service"_ : 

```
$ service ssh restart 
```

> _Verify that the "SSH Server" is listening at "port 22"_ :

```
┌──(root㉿kali)-[/home/kali]                                           

└─# netstat -tulpn :22                                                 

Active Internet connections (only servers)                                                                                                     
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:1883            0.0.0.0:*               LISTEN      1504/docker-proxy   
tcp        0      0 127.0.0.1:33115         0.0.0.0:*               LISTEN      969/containerd      

* ---> tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      76111/sshd: /usr/sb 

tcp        0      0 0.0.0.0:9392            0.0.0.0:*               LISTEN      1452/docker-proxy   
tcp6       0      0 :::1883                 :::*                    LISTEN      1511/docker-proxy   
tcp6       0      0 :::22                   :::*                    LISTEN      76111/sshd: /usr/sb 
tcp6       0      0 :::9392                 :::*                    LISTEN      1468/docker-proxy    
```




> [!NOTE]
> - Reduce exposure to "SSH port 22" by changing it to a "less obvious, non-standard port". This helps "obfuscate our operation" by selecting "a port" that "blends in" more naturally with other "network traffic".


```
┌──(root㉿tlosint)-[/etc/ssh]

└─# nano sshd_config
```


```
  GNU nano 8.3                                         sshd_config

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/local/bin:/usr/bin:/bin:/usr/games

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

Include /etc/ssh/sshd_config.d/*.conf

#Port 22
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::
```

> - ***Uncomment the "#port 22", and update this to "port number to 65328"*** : 


```
  GNU nano 8.3                                         sshd_config

# This sshd was compiled with PATH=/usr/local/bin:/usr/bin:/bin:/usr/games

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

Include /etc/ssh/sshd_config.d/*.conf

Port 65328
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
#LogLevel INFO

# Authentication:

LoginGraceTime 2m
PermitRootLogin prohibit-password
StrictModes yes
MaxAuthTries 6
MaxSessions 10

#PubkeyAuthentication yes
```





> - From Our command prompt, let's connect with the new altered port : 


```
C:\WINDOWS\system32> ssh root@192.168.2.18 -p 65328

root@192.168.2.18's password:

Linux kali 6.1.0-kali9-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.27-1kali1 (2023-05-12) x86_64

The programs included with the Kali GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Kali GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Jun 21 22:56:27 2023 from 192.168.2.30
┏━(Message from Kali developers)
┃
┃ This is a minimal installation of Kali Linux, you likely
┃ want to install supplementary tools. Learn how:
┃ ⇒ https://www.kali.org/docs/troubleshooting/common-minimum-setup/
┃
┗━(Run: “touch ~/.hushlogin” to hide this message)
```


# ***Accidental Delete of the SSH Host-Keys files -  sudo rm ssh_host***

> [!NOTE]
> - Prior to purging the "Installation of the OpenSSH-Server", let's try to generate the "Host-Keys,authorized keys".

```
$ ssh-keygen -A 
```  

> - _Purge and remove the entire installed OpenSSH-Server, and then let's give it one more try_ : 


> Run the below command : 

```
┌──(root㉿kali)-[/etc/ssh]                                                                     

└─# apt-get remove --purge openssh-server 

Reading package lists... Done              
Building dependency tree... Done       
Reading state information... Done      
The following packages were automatically installed and are no longer required:
  catfish dh-elpa-helper docutils-common gir1.2-xfconf-0 libcfitsio9 libgdal31 libmpdec3
  libnginx-mod-http-geoip libnginx-mod-http-image-filter libnginx-mod-http-xslt-filter
  libnginx-mod-mail libnginx-mod-stream libnginx-mod-stream-geoip libpoppler123 libprotobuf23
  libpython3.10 libpython3.10-dev libpython3.10-minimal libpython3.10-stdlib libtiff5
  libzxingcore1 nginx-common nginx-core openssh-sftp-server python-pastedeploy-tpl
  python3-alabaster python3-commonmark python3-docutils python3-imagesize python3-roman
  python3-snowballstemmer python3-speaklater python3-sphinx python3.10 python3.10-
```




> - Running the above, successfully removed all the files within this directory :


```
┌──(root㉿kali)-[/etc/ssh]

└─# ls       

ssh_config.d  sshd.config

```


 > - Re-install OpenSSH Server : 


```
┌──(root㉿kali)-[/etc/ssh]                                                                     

└─# apt-get install openssh-server                                           

Reading package lists... Done                                                                  

Building dependency tree... Done                                                               
Reading state information... Done                                                              
The following packages were automatically installed and are no longer required:
  catfish dh-elpa-helper docutils-common gir1.2-xfconf-0 libcfitsio9 libgdal31 libmpdec3
  libnginx-mod-http-geoip libnginx-mod-http-image-filter libnginx-mod-http-xslt-filter
  libnginx-mod-mail libnginx-mod-stream libnginx-mod-stream-geoip libpoppler123 libprotobuf23
  libpython3.10 libpython3.10-dev libpython3.10-minimal libpython3.10-stdlib libtiff5
  libzxingcore1 nginx-common nginx-core python-pastedeploy-tpl python3-alabas
```




> - New files would have been populated within this directory, "/etc/ssh" : 


```
  $ ls -larh /etc/ssh

┌──(root㉿kali)-[/etc/ssh]

└─# ls 

moduli        sshd_config         ssh_host_ecdsa_key.pub    ssh_host_rsa_key
ssh_config.d  sshd_config.d       ssh_host_ed25519_key      ssh_host_rsa_key.pub
sshd.config   ssh_host_ecdsa_key  ssh_host_ed25519_key.pub
```


> - Locate the "id_rsa" containing directory : 

```
┌──(root㉿kali)-[~/.ssh]
└─# ls              

id_rsa  id_rsa.pub  known_hosts  known_hosts.old
```

> - Generate a new private public key-pair : 

```
    $ ssh-keygen -t rsa 
```


> [!IMPORTANT]
> Make sure that the "SSH" directory has "permission of the chmod 700, --drwx---", whilst the authorized_keys, id_rsa.pub has "permission of 600 , -rw---"

```
┌──(root㉿kali)-[/etc/ssh]

└─# ls -larh ~/.ssh                 

total 24K
-rw-r--r--  1 root root  142 Apr 30 23:27 known_hosts.old
-rw-r--r--  1 root root  284 May  1 00:56 known_hosts
-rw-------  1 root root  563 May  1 11:34 id_rsa.pub
-rw-------  1 root root 2.6K May  1 11:34 id_rsa
drwx------ 22 root root 4.0K May  1 11:24 ..
drwx------  2 root root 4.0K May  1 11:39 .
```


> - Let's restart the "Openssh-Server" :

```
┌──(root㉿kali)-[~/.ssh]

$  service ssh restart
```


> [!NOTE]
> Fundamentally, the "ssh-copy-id" application allows us to connect over "SSH"and copy the "public key" over to the server we're trying to connect to.

```
┌──(root㉿kali)-[/etc/ssh]                        

└─# ssh-copy-id root@192.168.243.128                                                                

/usr/bin/ssh-copy-id: INFO: Source of key(s) to be installed: "/root/.ssh/id_rsa.pub"
/usr/bin/ssh-copy-id: INFO: attempting to log in with the new key(s), to filter out any that are already installed                                    
                                                  
/usr/bin/ssh-copy-id: ERROR: @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
ERROR: @    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
ERROR: @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
ERROR: IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!                                        
ERROR: Someone could be eavesdropping on you right now (man-in-the-middle attack)!
ERROR: It is also possible that a host key has just been changed.
ERROR: The fingerprint for the ED25519 key sent by the remote host is
ERROR: SHA256:cc0wC+/8+al1t0EnQwuwUNr9HpebWAfOBBvRksz0wMw.                                          
ERROR: Please contact your system administrator.                                                    
ERROR: Add correct host key in /root/.ssh/known_hosts to get rid of this message.
ERROR: Offending ED25519 key in /root/.ssh/known_hosts:1                                            
ERROR:   remove with:                             
ERROR:   ssh-keygen -f "/root/.ssh/known_hosts" -R "192.168.243.128"
ERROR: Host key for 192.168.243.128 has changed and you have requested strict checking.
ERROR: Host key verification failed.              

# This conflicting scenario, "Host Key Verification error occurs" due to the fact that, we just generated a new id_rsa key-pair while using the "ssh-keygen command".
# Another plausible explanation, is that this could not match the "local identity of the Server with the Remote Identity of the Server" from previous authentication.
```

> - _Remediate this situation using the command below_ : 

```
  $ ssh-keygen -f /root/.ssh/known_hosts -R 192.168.243.128
```

 > - _Similarly, we can also delete the "known_hosts" file to resolve this issue_ : 

```
    $ rm -f  /.ssh/known_hosts
```

```
┌──(root㉿kali)-[~/.ssh]                                                                             

└─# ssh-keygen -f /root/.ssh/known_hosts -R 192.168.243.128                                              

# Host 192.168.243.128 found: line 1  

/root/.ssh/known_hosts updated.                                                                          
Original contents retained as /root/.ssh/known_hosts.old         
```


> - _We'll now try to get into the server_ : 

```
  $ ssh root@192.168.243.128
```

```                                                                                 
┌──(root㉿kali)-[/etc/ssh]

└─# ssh root@192.168.243.128

root@192.168.243.128's password: 
Permission denied, please try again.
root@192.168.243.128's password: 
Permission denied, please try again.
root@192.168.243.128's password: 
root@192.168.243.128: Permission denied (publickey,password).
```


> - _Yet, we're still encountering some difficulties with the newly set-password_ : 

```
  $ dpkg-reconfigure openssh-server 
```


> - _If this persists, let's try to change the "root", passwd_ : 

```
    $ passwd root

Enter the new Password :
```


> # ***Continue Setup and IDS with FileBeat***


> - Let's create a "Network Interface" file and for this will first need to go into this directory, "/etc/network"


***Prior to any changes made onto the "interface file*** : 

```
┌──(root㉿kali)-[/etc/network]

└─# nano interfaces

{
# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
allow-hotplug eth0
iface eth0 inet dhcp
}
```



> [!NOTE]
>  Just as a quick "recapitulation" , "eth1" will be the interface that contains no "IP Addresss",  whilst eth0 will have a "statically assigned DHCP IP Address", and this is exactly what what we're are specifying in the "interface file" above.
> 
> _The below is the "entire network interface file" and there we've added few things, so that our interfaces are adjusted to reflect our design and topology._ 

> - ***Here is an equivalent of the "Network Interface File" designed for a Ubuntu Operating system*** : 

```
{ 
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

> - From here, let's add in some of the lines accordingly (check the pointers below) : 



> - Management interface

* ---> allow-hotplug eth0
* ---> iface eth0 inet dhcp

> - Sniffing interface

* ----> allow-hotplug eth1
* ----> iface eth1 inet manual
* ---> up ifconfig eth1 prmisc up
* --> down ifconfig  eth1 promisc down
}

```


> [!TIP]
> _In this tutorial, we've created two "network interfaces", one of them is under a NAT Network, whilst the other one is a "HOST-Only Network(constrained network), private address for our Kali Linux Machine"_
> ***Here are our "Network interface cards :***
> - eth0 : NAT Interface Card
> - eth1 : Host-Only Interface Card 

> - ***In our case, here's the equivalent of the "Network Interface File" for our "Kali OS"*** : 

```
{

# The loopback network interface
auto lo
iface lo inet loopback

# Management Interface
allow-hotplug eth0
iface eth0 inet dhcp

# Sniffing Interface
allow-hotplug eth1
iface eth1 inet manual
        up ifconfig eth1 promisc up
        down ifconfig eth1 promisc down
}

```

> [!NOTE]
> For Ubuntu User's we're trying to stop the "systemd-networkd", which is a network panner service and for Kali Users no need to worry about this. 


> ***From our Ubuntu command-Line Terminal, stop the service*** :

```
$ sudo service systemd-networkd stop
```

> ***Again for our Ubuntu Users, we will use another command to ensure complete removal, of the "netplan service"*** : 

```
  $ sudo apt remove netplan -y 
```


# ***Installing Suricata - Signature Based IDS***


> [!TIP]
> _For this tuturial, we have two options, however, we shall start with the "easiest one", first one as the second one requires us to "build and compile the file from source"._


> - ***Run this command to install "Suricata Stable",Version from its "repository"*** : 

```
    $  sudo apt install software-properties-common

```

> - ***Installation of Suricata*** : 

```
  $ sudo apt install suricata -y 

Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following packages were automatically installed and are no longer required:
  catfish dh-elpa-helper docutils-common gir1.2-xfconf-0
  libcfitsio9 libgdal31 libmpdec3 libnginx-mod-http-geoip
  libnginx-mod-http-image-filter
  libnginx-mod-http-xslt-filter libnginx-mod-mail
  libnginx-mod-stream libnginx-mod-stream-geoip
  libpoppler123 libprotobuf23 libpython3.10
  libpython3.10-dev libpython3.10-minimal
  libpython3.10-stdlib libtiff5 libzxingcore1 nginx-common
  nginx-core python-pastedeploy-tpl python3-alabaster
  python3-commonmark python3-docutils python3-imagesize                                                                   
  python3-snowballstemmer python3-speaklater
```




> # _Option 2_ : 


> - ***To begin with, we grabbed a ".gz version" of "Suricata Signature-Based-IDS", we're good to extracting the file, suricata-6.0.11.tar.gz :*** 


```
    $ tar xzf suricata-6.0.11.tar.gz
```

```
──(root㉿kali)-[/suricata-Signature-Based-IDS]

└─# ls

suricata-6.0.11  suricata-6.0.11.tar.gz
```



> -  ***Let's head into the directory suricata-6.0.11 and run the command to generate the "MakeFile" :***


```
   $ ./configure 
```

> # ***Build "Suricata", using the "make" commmand*** : 


```
  $ make install
```



> [!WARNING]
> _Some Encountered issues on the way, as try to run our update on our Kali Machine, we happen to experience that the URL's, for e,g , "www.kali.org" is not resolving to anything._


> -  ***Next we tried to update our "sources.list" at this directory :*** 

```
    $ sudo nano /etc/apt/sources.list
```

> - ***Let's add these 2 lines onto our file :***  

```
deb http://us.archive.kali.org/kali kali-rolling main non-free contrib
deb-src http://us.archive.kali.org/kali kali-rolling main non-free contrib
```



> [!NOTE]
> We'll now update the entire machine with this command : 

```
┌──(root㉿kali)-[/home/kali]

└─# apt update             

Ign:1 https://download.greenbone.net/apt/gb-stable/20.08 main/ InRelease                                   

Ign:2 http://http.kali.org/kali kali-rolling InRelease                                                     

Ign:3 http://us.archive.kali.org/kali kali-rolling InRelease        

Ign:3 http://us.archive.kali.org/kali kali-rolling 
InRelease                                               

Ign:1 https://download.greenbone.net/apt/gb-stable/20.08 main/ InRelease                                   

Ign:2 http://http.kali.org/kali kali-rolling InRelease   

```


> [!NOTE]
>  _Yet, we're still stuck at the InReleae step. Let's check our DNS Resolution with this command, right before let`s take a look at another
> command to add in the "network interface", "Ip Addrress, and all other related information :_ 

```
$ sudo nmtui
```


> - ***From the below, we can clearly see that our DNS Server is halting us :*** 


```

┌──(root㉿kali)-[/etc]

└─# nslookup 192.168.243.1

;; communications error to 192.168.243.1#53: timed out

```

> [!IMPORTANT]
> _Our next step will involve adding a namserver(Google DNS) in addition to our "Local DNS Server" (192.168.243.XX) to our directory, "/etc/resolv.conf"._ 
 
```
nameserver 8.8.8.8
nameserver 8.8.4.4      
```


> [!NOTE]
> Make sure that the "newly added", "nameservers" stays into the "resolv.conf", as this may occasionally, gets erased by itself after a booting process.
> Replace the <nameserver_IP> with the IP Address, of the nameserver 8.8.8.8 and 8.8.4.4 


> - ***Let's add each one by one :*** 

```
echo "nameserver <nameserver_IP>" | sudo tee -a /etc/resolvconf/resolv.conf.d/head

echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolvconf/resolv.conf.d/head

echo "nameserver 8.8.4.4" | sudo tee -a /etc/resolvconf/resolv.conf.d/head

```


> - ***Run the command to update the resolv.conf  :*** 

```
  $ sudo resolv.conf -u 
```
  
> - ***Install the resolvconf if needed :*** 

```
  $ apt-get install resolvconf  
```

> [!TIP]
> _Lastly, we'll nmow clear the apt cache, in case this is causing any sort of conflict :_ 

```
  $ apt clean
```





> # _Configuring Suricata Yaml_


> [!TIP]
> _In order to configure the "Suricata Yaml" file, let's make use of any editor and access the file at "/etc/suricata/suricata.yaml" :_ 

```
$ mousepad /etc/suricata/suricata.yaml 
```



> [!IMPORTANT]
> ***Ensure to replace the default interface, to your previously "assigned sniffing interface : eth0 " shown in the directory , "/etc/network/interfaces"***


> [!NOTE]
> _The HOME_NET CIDR corresponds to the Host-Only network  with interface card eth1 (the sniffing NIC)._
> _Consider naming your network as "HOME_NET", and in the "suricata.yaml" file, search for #HOME_NET and set the value for your network. (Don't uncomment these HOME_NET)_
 


> [!TIP]
> 
>  For the sake of clarity, we've included the interface file("/etc/network/interface") below, so that you may distinguish between the "sniffing interface and the management interface".  

 ```
 {
 
 GNU nano 7.2                              /etc/network/interfaces *                                      
 source /etc/network/interfaces.d/*
 
 # The loopback network interface
 auto lo
 iface lo inet loopback
 
 # management interface
 allow-hotplug eth0
 iface eth0 inet dhcp
 
 # sniffing interface
 allow-hotplug eth1
 iface eth1 inet manual
 up ifconfig eth1 promisc up
 down ifconfig eth1 promisc down
 }
```






> [!NOTE]
> _Change the following lines, within the "suricata.yaml(/etc/suricata/suricata.yaml) file" and also add in the "Sniffing NIC Address, Network Address , eth1", as well as addding a corresponding "Subnet Mask, /24"_ 
> - ***Do not forget to change modify the interface from eth0 --> eth1***
> - _Take note that we intentionally, added a new "HOME_NET" Address which matches that of our "Host-Only Network", in addition we also "uncommented" it, as follows, HOME_NET:"[192.168.233.0/24]"_  
 > - ***Add in this line correspondoing to our actual `Home_Network` --->>>   HOME_NET:"[192.168.233.0/24]"***

```
vars:
  # more specific is better for alert accuracy and performance
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    #HOME_NET: "[192.168.0.0/16]"
    #HOME_NET: "[10.0.0.0/8]"
    #HOME_NET: "[172.16.0.0/12]"
    #HOME_NET: "any"
  ```


> [!IMPORTANT]
> - ***Make sure to change/disable, "chechsum validation : No", and the reason for this, is we want to avoid "rejecting or dropping off packets", in case if the "packet capture" software being used, oversees the captured packets not passing the "checksum validation."***
> - ***Change this setting to `no` #   checksum-validation: yes/ = `no`    # To validate the checksum of received***


```
# Stream engine settings. Here the TCP stream tracking and reassembly 
# engine is configured.
#
# stream:
#   memcap: 64mb                # Can be specified in kb, mb, gb.  Just a
#                               # number indicates it's in bytes.
#   memcap-policy: ignore       # Can be "drop-flow", "pass-flow", "bypass",
#                               # "drop-packet", "pass-packet", "reject" or
#                               # "ignore" default is "ignore"
```





> # _Creating a "Service File for Suricata(Start or Stop, for e.g service ssh start)_

> ***Great, we're good to use to Suricata, however, we would need to use "command-line arguments", to get this to start each and every time(rather lengthy and cumbersome)_***

> [!IMPORTANT]
> _In our very case a there exists already a `service file`, for `Suricata`._



> - ***Let's head to the below directory and start to create "suricata.service" file :****  

```
  $ sudo nano /lib/systemd/system/suricata.service
```

```
[Unit]
# At the beginning of any service, very important to give a Description.
Description=Suricata Intrusion Detection Service

# When can the Service Start. 
After=syslog.target network-online.target 


[Service]
# Environment file to pick up $OPTIONS. On Fedora/EL this would be 
# /etc/sysconfig/suricata, or on Debian/Ubuntu, /etc/default/suricata.

# Here are the "Environmental Variables", which are going to be used. 
#EnvironmentFile=/etc/sysconfig/suricata
#EnvironmentFile=-/etc/default/suricata

# The below will reset the "Process PID" file, everytime prior to starting the "suricata.service". 
ExeceStartPre=/bin/rm -f /var/run/suricata.pid 

# The below is the "command-line argument" which will be used "everytime" the service starts.

# File Path : /usr/bin/suricata 
# Configuration Path : -c /etc/suricata/suricata.yaml
# Process ID File Stored : --pidfile /var/run/suricata.pid 
# Special command, that describes how the interface will be managing the packet capture and inspection.(other type exists, like pf ring) : --af-packet  
ExecStart= /usr/bin/suricata -c /etc /suricata/suricata.yaml --pidfile /var/run/suricata.pid --af-packet

# On the reload, this will kill the service.( Starting with /bin/kill, then the User, -USR2, and finally the process ID, PID  $MAINPID) 

ExecReload=/bin/kill -USR2 $MAINPID  

[Install]
WantedBy=multi-user.target
```

> -  ***Under the current Version of Suricata, there seem to be a similar version of what we have gone through above (almost the same) :*** 

```
  GNU nano 7.2       /lib/systemd/system/suricata.service                
[Unit]
Description=Suricata IDS/IDP daemon
After=network.target network-online.target
Requires=network-online.target
Documentation=man:suricata(8) man:suricatasc(8)
Documentation=https://suricata-ids.org/docs/

[Service]
Type=forking
#Environment=LD_PRELOAD=/usr/lib/libtcmalloc_minimal.so.4
PIDFile=/run/suricata.pid
ExecStart=/usr/bin/suricata -D --af-packet -c /etc/suricata/suricata.yam>
ExecReload=/usr/bin/suricatasc -c reload-rules ; /bin/kill -HUP $MAINPID
ExecStop=/usr/bin/suricatasc -c shutdown
Restart=on-failure
ProtectSystem=full
ProtectHome=true


[Install]
WantedBy=multi-user.target
```





> # _Network Threat Hunting with Zeek_


> -  ***In order to take advantage of Zeek, we'll need to get this installed locally. Not only does zeek provides us with that additional edge with deep packet level inspection but also does provide "rich parsing of packet metadata",***
> -  ***which allow us to perform "understanding what a protocol is doing and what commands are being sent."***.
> -  This tool has greatly been improved from the start till its very end allowing an out of the box experience. Installation now includes one liner bash  installation which also comes with RITA which again allows for a great visualization using different know the techniques such as common aggregation of data points hence allowing us to easily spot suspicious activities in heavy traffic environment.

 > - ***Execute the command below to install both RITA and Zeek altogether :*** 

```
wget https://github.com/activecm/rita/releases/download/v5.0.8/install-rita-zeek-here.sh

chmod +x install-rita-zeek-here.sh

./install-rita-zeek-here.sh
```


> [!TIP]
> 
> ***Since this will be taking a lot of time, from Settings --> "power management" --> ScreenTimeout set to "Never" to prevent the screen from timeing out during the "compilation" process.***


```
Changing the Keep-Alive Default message to 300 Seconds
For convenience purposes, we want to resume our entire work at any point in time on "Windows, Command Prompt", using our Server as the only Option.
 - Configure DropBear Server's Keep-Alive, by heading to its "configuration file", "/etc/default/dropbear". 
From there, add in the "option" to "bypass" its "Default Keep-Alive" and set this to 300 seconds instead of 60 Seconds.
```



> # Configuring Zeek after installation(Adding Zeek to our "Path

> ***Here is the last step, that will allow us to call on "Zeek within the Terminal" and this will be usually done through "/etc" environment file.*** 




> [!TIP]
> ***Allow the necessary change for this to work with the linux distribution by adding in the following "path" for "zeek" : "/usr/local/zeek/bin"***.

 ```
┌──(root㉿kali)-[/opt/zeek]

└─# sudo visudo

# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
Defaults        env_reset
Defaults        mail_badpass

# * --->> Add this in here : Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/zeek/bin"

# This fixes CVE-2005-4890 and possibly breaks some versions of kdesu
# (#1011624, https://bugs.kde.org/show_bug.cgi?id=452532)
Defaults        use_pty

# This preserves proxy settings from user environments of root
# equivalent users (group sudo)
#Defaults:%sudo env_keep += "http_proxy https_proxy ftp_proxy all_proxy no_proxy"

# This allows running arbitrary commands, but so does ALL, and it means
# different sudoers have their choice of editor respected.
#Defaults:%sudo env_keep += "EDITOR"

# Completely harmless preservation of a user preference.
#Defaults:%sudo env_keep += "GREP_COLOR"

# While you shouldn't normally run git as root, you need to with etckeeper
#Defaults:%sudo env_keep += "GIT_AUTHOR_* GIT_COMMITTER_*"

# Per-user preferences; root won't have sensible values for them.
#Defaults:%sudo env_keep += "EMAIL DEBEMAIL DEBFULLNAME"

# "sudo scp" or "sudo rsync" should be able to use your SSH agent.
#Defaults:%sudo env_keep += "SSH_AGENT_PID SSH_AUTH_SOCK"

# Ditto for GPG agent
#Defaults:%sudo env_keep += "GPG_AGENT_INFO"

# Host alias specification

# User alias specification

# Cmnd alias specification

# User privilege specification
root    ALL=(ALL:ALL) ALL

# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "@include" directives:

@includedir /etc/sudoers.d
```



> [!IMPORTANT]
>  Add `Zeek PATH` to your `system's PATH environmental variable` by adding the following line, `export PATH=$PATH:/usr/local/go/bin` to our `path, "~/.zhsrc, ~/.bashrc"`. 


```
──(root㉿kali)-[/usr/local/zeek/bin]

└─# nano ~/.zshrc
```

```
┌──(root㉿kali)-[/usr/local/zeek/bin]

└─# nano ~/.bashrc

....                                                     

# PATH EXPORT                                                                                
                                                                                             
export PATH=$PATH:/usr/local/zeek/bin

```


> [!IMPORTANT]
> - Export PATH, to "~/.zshrc, ~/.bashrc", allows us to run `Zeek`, without the need to `enter Zeek's full location path`.
> - ***Add the "export PATH=$PATH:/usr/local/go/bin" to the very end of "/.zshrc && /.bashrc".***

> _Access these two location from our `Linux Terminal` and add the corresponding `export PATH` :_

```
$ nano ~/.bashrc 
```

```
$ nano /.zshrc
```




> # _Configuration of Zeek files - Specifying the IP ranges + Node + (zeek)Control_



> - ***These are the 3 files which we would need to modify :*** 

```
┌──(root㉿kali)-[/usr/local/zeek/etc]

└─# ls 

networks.cfg  node.cfg  zeekctl.cfg  zkg
```
                                           

> - ***Configure the network configuration for "zeek" at this location ; "nano /usr/loca/zeek/etc/networks.cfg"***

>   _See what the "file" network.cfg looks like ;_

```                                                                                                
# List of local networks in CIDR notation, optionally followed by a descriptive
# tag. Private address space defined by Zeek's Site::private_address_space set
# (see scripts/base/utils/site.zeek) is automatically considered local. You can
# disable this auto-inclusion by setting zeekctl's PrivateAddressSpaceIsLocal
# option to 0.
#
# Examples of valid prefixes:
#
# 1.2.3.0/24        Admin network
# 2607:f140::/32    Student network 

192.168.2.0/24   Private IP Space 
```

> [!NOTE]
> ***Take note of how we've added, the 192.168.2.0/24(unhash, without the #) , and this corresponds to our "HOME_NET" under Suricata which is our default "Network Address of eth0 : 192.168.2.0/24"***
 

>  ***Configuration of the `zeek node`***


> -  _Let's proceed to this path itself and modify, the "Sniffing Interface" :_ 

```
     $ sudo nano /usr/local/zeek/etc/node.cfg 

# Example ZeekControl node configuration.
# This example has a standalone node ready to go except for possibly changing
# the sniffing interface.

# This is a complete standalone configuration.  Most likely you will

# only need to change the interface.

[zeek]
type=standalone
host=localhost
# Change the interface here to eth1(sniffing interface) * ---->> interface=eth1

## Below is an example clustered configuration. If you use this,
## remove the [zeek] node above.

#[logger-1]
#type=logger
#host=localhost
#
#[manager]
#type=manager
#host=localhost
#
#[proxy-1]
#type=proxy
#host=localhost
#
#[worker-1]
#type=worker
#host=localhost
#interface=eth0
#
#[worker-2]
#type=worker
#host=localhost
#interface=eth0

```

> ***Setup "zeekctl.cfg" which is the zeek control orchestration "application", it controls event of logging, amd control "clusters".***

>  _Let's make our way to the following location  : /usr/local/zeek/etc/zeekctl.cfg :_ 

```

# Mail connection summaries are sent once per log rotation interval.
# Requires the trace-summary script. 1 = send mail, 0 = do not send.

> - Set to "0",  MailConnectionSummary = 1 / "0"

MailConnectionSummary = 0

# Lower threshold (percent) for free space on the filesystem that holds SpoolDir.
# If free space drops below this, "zeekctl cron" sends warning emails.
# 0 disables the check.

> - Set to "0", MinDiskSpace = 5 / "0"

MinDiskSpace = 0

# Send mail when a cluster host's availability changes.
# 1 = send mail, 0 = do not send.

> - Set to "0", MailHostUpDown = "0"

MailHostUpDown = 0

# Expiration interval for archived logs deleted by "zeekctl cron".
# Format: integer followed by a unit: day, hr, or min. 0 = never expire.

> - Set to "1 for daily", LogExpireInterval = 1 (A value of 0 means that logs never expire) 

LogExpireInterval = 1 day

# Write stats to stats.log. 1 = enable, 0 = disable. 
# Means write to stats.log, and a value of 0 means do not write to stats.log.

> - Set this to "0" StatsLogEnable = 0 (This entry never expire)

StatsLogEnable = 0

# How long to keep entries in stats.log. 0 = never expire.
# If you prefer one day, set to 1 (days).

> -  Set this to "1" StatsLogExpireInterval = 1

StatsLogExpireInterval = 1

# Directory used for archived logs (rotation target). Make sure this matches your Filebeat path.
LogDir = /var/log/zeek/logs

```

> [!IMPORTANT]
> In this same `document`, configure the `archive directory` used at `each log rotation`.
> The `path` must `match the setting` below; otherwise `Filebeat` may have `difficulty` collecting the `rotated logs`.
> ***LogDir = /var/log/zeek/logs***


> # _Create ZeekCtl Cron job_

> _ZeekCtl would require crontab to setup "Log Rotation" activities, and cronjob will run every 5 mins with log rotation as follows :_ 

```
# m  h  dom mon dow   command

*/5 *  *   *   *     /usr/local/zeek/bin/zeekctl cron

`dom = day of month, mon = month, dow = day of week`

```

> - ***Let's add in the `cronjob` :*** 

```

$ crontab -e 


  GNU nano 7.2                     /tmp/crontab.pjEolF/crontab                                           
# Edit this file to introduce tasks to be run by cron.
# 
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
# 
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').
# 
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
# 
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
# 
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
# 
# For more information see the manual pages of crontab(5) and cron(8)
# 

# m h  dom mon dow   command
*/5 * * * *  /usr/local/zeek/bin/zeekctl cron

```


> # _Change Configuration Output Format of the logs to Json - Policy Tuning_ 


> [!NOTE]
> Interestingly, we would want to change the "configuration output format" of the logs to "JSON" and to accomplish this will move to the very "bottom" of the page, and search through and alter as well as add in the line below :  


```
$  sudo  nano /usr/local/zeek/share/zeek/site/local.zeek
```

```
{
# Output to JSON
@load policy/tuning/json-logs.zeek 
}


# This is how this "local.zeek" looks like ; 



{
##! Local site policy. Customize as appropriate.
##!
##! This file will not be overwritten when upgrading or reinstalling!



# Installation-wide salt value that is used in some digest hashes, e.g., for
# the creation of file IDs. Please change this to a hard to guess value.
redef digest_salt = "Please change this value.";



# This script logs which scripts were loaded during each run.
@load misc/loaded-scripts



# Apply the default tuning scripts for common tuning settings.
@load tuning/defaults



# Estimate and log capture loss.
@load misc/capture-loss



# Enable logging of memory, packet and lag statistics.
@load misc/stats



# For TCP scan detection, we recommend installing the package from
# 'https://github.com/ncsa/bro-simple-scan'. E.g., by installing it via
#
#     zkg install ncsa/bro-simple-scan



# Detect traceroute being run on the network. This could possibly cause
# performance trouble when there are a lot of traceroutes on your network.
# Enable cautiously.
#@load misc/detect-traceroute



# Generate notices when vulnerable versions of software are discovered.
# The default is to only monitor software found in the address space defined
# as "local".  Refer to the software framework's documentation for more
# information.
@load frameworks/software/vulnerable



# Detect software changing (e.g. attacker installing hacked SSHD).
@load frameworks/software/version-changes



# This adds signatures to detect cleartext forward and reverse windows shells.
@load-sigs frameworks/signatures/detect-windows-shells



# Load all of the scripts that detect software in various protocols.
@load protocols/ftp/software
@load protocols/smtp/software
@load protocols/ssh/software
@load protocols/http/software
# The detect-webapps script could possibly cause performance trouble when
# running on live traffic.  Enable it cautiously.
#@load protocols/http/detect-webapps



# This script detects DNS results pointing toward your Site::local_nets
# where the name is not part of your local DNS zone and is being hosted
# externally.  Requires that the Site::local_zones variable is defined.
@load protocols/dns/detect-external-names



# Script to detect various activity in FTP sessions.
@load protocols/ftp/detect



# Scripts that do asset tracking.
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/ssl/known-certs



# This script enables SSL/TLS certificate validation.
@load protocols/ssl/validate-certs



# This script prevents the logging of SSL CA certificates in x509.log
@load protocols/ssl/log-hostcerts-only



# If you have GeoIP support built in, do some geographic detections and
# logging for SSH traffic.
@load protocols/ssh/geo-data
# Detect hosts doing SSH bruteforce attacks.
@load protocols/ssh/detect-bruteforcing
# Detect logins using "interesting" hostnames.
@load protocols/ssh/interesting-hostnames



# Detect SQL injection attacks.
@load protocols/http/detect-sqli



#### Network File Handling ####



# Enable MD5 and SHA1 hashing for all files.
@load frameworks/files/hash-all-files



# Detect SHA1 sums in Team Cymru's Malware Hash Registry.
@load frameworks/files/detect-MHR



# Extend email alerting to include hostnames
@load policy/frameworks/notice/extend-email/hostnames



# Extend the notice.log with Community ID hashes
# @load policy/frameworks/notice/community-id



# Enable logging of telemetry data into telemetry.log and
# telemetry_histogram.log.
@load frameworks/telemetry/log



# Uncomment the following line to enable detection of the heartbleed attack. Enabling
# this might impact performance a bit.
# @load policy/protocols/ssl/heartbleed



# Uncomment the following line to enable logging of Community ID hashes in
# the conn.log file.
# @load policy/protocols/conn/community-id-logging



# Uncomment the following line to enable logging of connection VLANs. Enabling
# this adds two VLAN fields to the conn.log file.
# @load policy/protocols/conn/vlan-logging


> - Uncomment the following line to enable logging of link-layer addresses. Enabling

# this adds the link-layer address for each connection endpoint to the conn.log file.
# @load policy/protocols/conn/mac-logging




> - This is where we'd add the line : 

# Output to JSON
@load policy/tuning/json-logs.zeek 


# Uncomment this to source zkg's package state
# @load packages

}
```


> [!NOTE]
> _The above configuration will direcct "zeekctl", to log into a `file directory`, however this `doesn't exist as of yet`_

>  ***_Our next step : Create a file logging location `/var/logs/zeek/logs`_***

```
┌──(root㉿kali)-[/var/log]

└─# mkdir zeek


┌──(root㉿kali)-[/var/log/zeek]  

  $ mkdir  -p logs 

┌──(root㉿kali)-[/var/log/zeek]

└─# ls 

logs

```






> # _FileBeat Agent Installation + Signing Key Download  + Add Elastic Stable Repository  + Add apt-transport-https_



> [!NOTE]
> _Filebeat is an "agent" which will be in "charge of taking our logs" and place them into "elastic search" for "visualization purposes"(Kibana)._ 
>_ We'll first be downloading its `signing key installation` is in `GPG` which stands for `GNU Privacy Guard` and is better known as `GnuPG` or just `GPG`, is an `implementation` of `public key cryptography`._



```
 ┌──(root㉿kali)-[/var/log/zeek/logs]

└─#  wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add - 

Warning: apt-key is deprecated. Manage keyring files in trusted.gpg.d instead (see apt-key(8)).
OK
```




>  ***Add the repository from ` Elastic stable main` branch*** : 


> [!IMPORTANT]
>   _Let's first make sure to install the package for `https transport` as this allows `encryption and authentication over https`_ : 

  $ sudo apt-get install apt-transport-https 




┌──(root㉿kali)-[/var/log/zeek/logs]


└─# echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list



>>>>>> deb https://artifacts.elastic.co/packages/7.x/apt stable main




# Let us update the "existing repository" with the changes brought :


┌──(root㉿kali)-[/var/log/zeek/logs]

└─# sudo apt update  

Get:2 https://artifacts.elastic.co/packages/7.x/apt stable InRelease [13.7 kB]
Ign:3 https://download.docker.com/linux/ubuntu kali-rolling InRelease        
Err:4 https://download.docker.com/linux/ubuntu kali-



# We're good to install the filebeat agent( contains different modules, like suricata, zeek apache server logs, firewall logs) : 


  $ sudo apt install -y filebeat

Reading package lists... Done                                                        
Building dependency tree... Done
Reading state information... Done                                                    
The following packages were automatically installed and are no longer required:
bluez-firmware debugedit dh-elpa-helper docutils-common figlet finger firebird3.0-common firebird3.0-common-doc firmware-ath9k-htc firmware-atheros firmware-brcm80211
firmware-intel-sound firmware-iwlwifi firmware-libertas firmware-realtek firmware-sof-signed firmware-ti-connectivity firmware-zd1211 freerdp2-x11 gdal-data
gdal-plugins kali-linux-firmware libaec0 l


# Note : At the time of writing, eleastic may have changed their infrastructure, where there could be a single elastic agant that controls all the beats .. That could have been much easier for us as it does incorporate, new features like fleet central management for "Zeek and Suricata". 






> # Configuring the filebeat Configuration File


# Let's access our "filebeat configuration" file and this contains the "setup for your log paths" :


Hints : Look out for the "Kibana Section" at the bottom of this file and remove the "#, hash" , as in the below : 

  host: "localhost:5601" 


  $ sudo nano `/etc/filebeat/filebeat.yml`





{ 
###################### Filebeat Configuration Example #########################



# This file is an example configuration file highlighting only the most common
# options. The filebeat.reference.yml file from the same directory contains all the
# supported options with more comments. You can use it as a reference.
#
# You can find the full configuration reference here:
# https://www.elastic.co/guide/en/beats/filebeat/index.html



# For more available modules and options, please see the filebeat.reference.yml sample
# configuration file.



# ============================== Filebeat inputs ===============================

filebeat.inputs:

# Each - is an input. Most options can be set at the input level, so
# you can use different inputs for various configurations.
# Below are the input specific configurations.

# filestream is an input for collecting log messages from files.
- type: filestream

  # Unique ID among all inputs, an ID is required.
  id: my-filestream-id

  # Change to true to enable this input configuration.
  enabled: false

=

  # Paths that should be crawled and fetched. Glob based paths.
  paths:

    - /var/log/*.log
    #- c:\programdata\elasticsearch\logs\*

  # Exclude lines. A list of regular expressions to match. It drops the lines that are
  # matching any regular expression from the list.
  #exclude_lines: ['^DBG']

  # Include lines. A list of regular expressions to match. It exports the lines that are
  # matching any regular expression from the list.
  #include_lines: ['^ERR', '^WARN']

  # Exclude files. A list of regular expressions to match. Filebeat drops the files that
  # are matching any regular expression from the list. By default, no files are dropped.
  #prospector.scanner.exclude_files: ['.gz$']

  # Optional additional fields. These fields can be freely picked
  # to add additional information to the crawled log files for filtering
  #fields:
  #  level: debug
  #  review: 1
# ============================== Filebeat modules ==============================

filebeat.config.modules:
  # Glob pattern for configuration loading
  path: ${path.config}/modules.d/*.yml

  # Set to true to enable config reloading
  reload.enabled: false

  # Period on which files under path should be checked for changes
  #reload.period: 10s

# ======================= Elasticsearch template setting =======================

setup.template.settings:
  index.number_of_shards: 1
  #index.codec: best_compression
  #_source.enabled: false

# ================================== General ===================================

# The name of the shipper that publishes the network data. It can be used to group
# all the transactions sent by a single shipper in the web interface.
#name:

# The tags of the shipper are included in their own field with each
# transaction published.
#tags: ["service-X", "web-tier"]


# Optional fields that you can specify to add additional information to the
# output.
#fields:
#  env: staging
# ================================= Dashboards =================================

# These settings control loading the sample dashboards to the Kibana index. Loading
# the dashboards is disabled by default and can be enabled either by setting the
# options here or by using the `setup` command.
#setup.dashboards.enabled: false

# The URL from where to download the dashboards archive. By default this URL
# has a value which is computed based on the Beat name and version. For released
# versions, this URL points to the dashboard archive on the artifacts.elastic.co
# website.

#setup.dashboards.url:



# =================================== Kibana ===================================



# Starting with Beats version 6.0.0, the dashboards are loaded via the Kibana API.
# This requires a Kibana endpoint configuration.

setup.kibana:

  # Kibana Host
  # Scheme and port can be left out and will be set to the default (http and 5601)
  # In case you specify and additional path, the scheme is required: http://localhost:5601/path
  # IPv6 addresses should always be defined as: https://[2001:db8::1]:5601
  


  * >>>> { This is where we would remove the # and we could have instead added an "IP Address" of where you have the "elastic stack" set up, rather than the localhost }  host: "localhost:5601"



  # Kibana Space ID
  # ID of the Kibana Space into which the dashboards should be loaded. By default,
  # the Default Space will be used.
  #space.id:




# =============================== Elastic Cloud ================================



# These settings simplify using Filebeat with the Elastic Cloud (https://cloud.elastic.co/).
# The cloud.id setting overwrites the `output.elasticsearch.hosts` and
# `setup.kibana.host` options.
# You can find the `cloud.id` in the Elastic Cloud web UI.
#cloud.id:

# The cloud.auth setting overwrites the `output.elasticsearch.username` and
# `output.elasticsearch.password` settings. The format is `<user>:<pass>`.
#cloud.auth:

# ================================== Outputs ===================================

# Configure what output to use when sending the data collected by the beat.





>>
>>>>
>>>>>>> The section below is wehere we would replace the localhost, with the "url", of the "elastic cloud deployment". 


   # Remember  : This section is only for those who're setting "Elastic Cloud" : 


# ---------------------------- Elasticsearch Output ----------------------------




output.elasticsearch:

  # Array of hosts to connect to.

>>>>  # As indicated below, is where you would be setting the "Elastic Cloud", URL :

  hosts: ["localhost:9200"]


  # Protocol - either `http` (default) or `https`.
  #protocol: "https"


>>>>>>>>>>>
>>>>>>>
>>>>    # In case you would have set up an elastic cloud, then this would have to be secured, using a "username and password" from the fields below. 
>>
  # Authentication credentials - either API key or username/password.
  #api_key: "id:api_key"
  #username: "elastic"
  #password: "changeme"
>>>>>

# ------------------------------ Logstash Output -------------------------------

#output.logstash:

  # The Logstash hosts
#hosts: ["localhost:5044"]

  # Optional SSL. By default is off.
  # List of root certificates for HTTPS server verifications
  #ssl.certificate_authorities: ["/etc/pki/root/ca.pem"]

  # Certificate for SSL client authentication
  #ssl.certificate: "/etc/pki/client/cert.pem"

  # Client Certificate Key
  #ssl.key: "/etc/pki/client/cert.key"



# ================================= Processors =================================

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: ~
  - add_docker_metadata: ~
  - add_kubernetes_metadata: ~

# ================================== Logging ===================================



# Sets log level. The default log level is info.
# Available log levels are: error, warning, info, debug
#logging.level: debug



# At debug level, you can selectively enable logging only for some components.
# To enable all selectors use ["*"]. Examples of other selectors are "beat",
# "publisher", "service".
#logging.selectors: ["*"]



# ============================= X-Pack Monitoring ==============================

# Filebeat can export internal metrics to a central Elasticsearch monitoring
# cluster.  This requires xpack monitoring to be enabled in Elasticsearch.  The
# reporting is disabled by default.

# Set to true to enable the monitoring reporter.
#monitoring.enabled: false

# Sets the UUID of the Elasticsearch cluster under which monitoring data for this
# Filebeat instance will appear in the Stack Monitoring UI. If output.elasticsearch

# is enabled, the UUID is derived from the Elasticsearch cluster referenced by output.elasticsearch.

#monitoring.cluster_uuid:

# Uncomment to send the metrics to Elasticsearch. Most settings from the
# Elasticsearch output are accepted here as well.
# Note that the settings should point to your Elasticsearch *monitoring* cluster.
# Any setting that is not set is automatically inherited from the Elasticsearch
# output configuration, so if you have the Elasticsearch output configured such
# that it is pointing to your Elasticsearch monitoring cluster, you can simply
# uncomment the following line.
#monitoring.elasticsearch:

# ============================== Instrumentation ===============================



# Instrumentation support for the filebeat.

#instrumentation:
    # Set to true to enable instrumentation of filebeat.
    #enabled: false



    # Environment in which filebeat is running on (eg: staging, production, etc.)
    #environment: ""

    # APM Server hosts to report instrumentation results to.
    #hosts:

    #  - http://localhost:8200

    # API Key for the APM Server(s).
    # If api_key is set then secret_token will be ignored.
    #api_key:
    # Secret token for the APM Server(s).
        #secret_token:


# ================================= Migration ==================================

# This allows to enable 6.7 migration aliases
#migration.6_to_7.enabled: true

}


                    ***********//// Enabling the FileBeat Modules + Changing "Zeek Modules Default Path" /////**********************


# We'll now enable the filebeat modules :   




  (root@kali)-[/var/log/zeek/logs]


    $ sudo filebeat modules enable zeek suricata

Enabled zeek 
Enabled suricata






# Change the "Zeek" modules "default path" : 


    $ sudo nano /etc/filebeat/modules.d/zeek.yml



# Go at the very bottom, and add the following line to "var.paths" :  

  ssl:
    enabled: true
  stats:
    enabled: true
  syslog:
    enabled: true
  traceroute:
    enabled: true
  tunnel:
    enabled: true
  weird:
    enabled: true
  x509:
    enabled: true

>>>>  # Set custom paths for the log files. If left empty,
>>>>  # Filebeat will choose the paths depending on your OS.
  >>>>
  >>>   # Make sure to remove the {hash,#} such that the path namely, var.paths, can be applied.
  >>
  >>   var.paths: [/var/log/zeek/logs/current/*.log]  >>> *, wildcard , means that this will "gather" the "logs" as they come. 

 



              ****************//////// Create Filebeat Keystore  +  modify {ElasticSearch Output section - Keystore Version} ////////***********************



- Let's analyse how the structure, of the "keystore", looks like : 


#  Check how the "filebeat keystore" has a definite structure as shown below : 


- es : elastic search
- host, pwd, users :  artifacts

hosts: ["$(es_host)"] 

username: "${es_users}"
password: "${es_pwd}"


# We'll begin creating a "filebeat keystore", let us use the following command :


  $ sudo filebeat keystore create 


# Add the filebeat keystore, here we're assuming that the keystore should bear the name elastic search, "shortnamed" for "es" and the "artifacts", users : 


  $ sudo filebeat keystore add es_user


- Note: Legends, indicate modification area  : >>>




# Let's head into this current file : /etc/filebeat/filebeat.yml 


# Note  : As a best practice, there may be some people who will be connecting a "filebeat agent" or another agent to communicate with Elastic. 


- In these cases, we may have a  filebeat "keystore", which basically stores all the information like "password, Users", in an environmental variable/encrypted file.



Let's start affecting the change at the "ElasticSearch Output" Section : 



    $ nano /etc/filebeat/filebeat.yml


{

>>>>>
>>>>
>>>
# ============================== Filebeat modules ==============================

filebeat.config.modules:
  # Glob pattern for configuration loading
  path: ${path.config}/modules.d/*.yml

  # Set to true to enable config reloading
  reload.enabled: false

  # Period on which files under path should be checked for changes
  #reload.period: 10s

# ======================= Elasticsearch template setting =======================

setup.template.settings:
  index.number_of_shards: 1
  #index.codec: best_compression
  #_source.enabled: false



# =================================== Kibana ===================================

# Starting with Beats version 6.0.0, the dashboards are loaded via the Kibana API.
# This requires a Kibana endpoint configuration.
setup.kibana:

  # Kibana Host
  # Scheme and port can be left out and will be set to the default (http and 5601)
  # In case you specify and additional path, the scheme is required: http://localhost:5601/path
  # IPv6 addresses should always be defined as: https://[2001:db8::1]:5601
  host: "localhost:5601"

  # Kibana Space ID
  # ID of the Kibana Space into which the dashboards should be loaded. By default,
  # the Default Space will be used.
  #space.id:

# =============================== Elastic Cloud ================================

# These settings simplify using Filebeat with the Elastic Cloud (https://cloud.elastic.co/).

# The cloud.id setting overwrites the `output.elasticsearch.hosts` and
# `setup.kibana.host` options.
# You can find the `cloud.id` in the Elastic Cloud web UI.
#cloud.id:

# The cloud.auth setting overwrites the `output.elasticsearch.username` and
# `output.elasticsearch.password` settings. The format is `<user>:<pass>`.
#cloud.auth:

# ================================== Outputs ===================================

# Configure what output to use when sending the data collected by the beat.



>>>
>>>>>> # It is at this section we would make some modification. 
>>>>
>>
# ---------------------------- Elasticsearch Output ----------------------------
output.elasticsearch:
  # Array of hosts to connect to.
 
 >>>>>>
 >>>> Our hosts will be different compared to the below : 
 

 # "Right keystore" >>>>  hosts:["${es_host}"] 

 >>>
{
  hosts: ["localhost:9200"]
}
  # Protocol - either `http` (default) or `https`.
  #protocol: "https"

  # Authentication credentials - either API key or username/password.
  #api_key: "id:api_key"



  
  >>>>>>>
  >>>>>># This is where our keystore, would be a little different than the below ... 
  >>>>> username: "${es_user}"
  >>>> password: "${es_user}"
  >>


# Originally, this is what it looks like : 
 {
  #username: "elastic"
  #password: "changeme"
}





                    ****************//// Deploy/Status/Start  Filebeat/Suricata/zeekctl ////******************


# WinlogBeat and AuditBeat are the mostly used, and this is what we're using in this tutorial. 


# Since it is our first time using "filebeat" for this particular elastic cluster, then this would not have been "setup" yet, so let's install it through the command below , and this will install all the "index templates", "index patterns", "dashboards and visualizations" which are default to filebeat ..  


    $ sudo filebeat setup -e


# The below allows us to update to an emerging "Suricata ruleset" (IDS) from an open-source repository, and it is best to run the "update" command, right after installing "Suricata". 

 
┌──(root㉿kali)-[/home/kali]

└─# suricata-update             

19/5/2023 -- 09:51:35 - <Info> -- Using data-directory /var/lib/suricata.
19/5/2023 -- 09:51:35 - <Info> -- Using Suricata configuration /etc/suricata/suricata.yaml
19/5/2023 -- 09:51:35 - <Info> -- Using /etc/suricata/rules for Suricata provided rules.
19/5/2023 -- 09:51:35 - <Info> -- Found Suricata version 6.0.10 at /usr/bin/suricata.
19/5/2023 -- 09:51:35 - <Info> -- Loading /etc/suricata/suricata.yaml
19/5/2023 -- 09:51:35 - <Info> -- Disabling rules for protocol http2
19/5/2023 -- 09:51:35 - <Info> -- Disabling rules for protocol modbus
19/5/2023 -- 09:51:35 - <Info> -- Disabling rules for protocol dnp3
19/5/2023 -- 09:51:35 - <Info> -- Disabling rules for protocol enip
19/5/2023 -- 09:51:35 - <Info> -- No sources configured, will use Emerging Threats Open
19/5/2023 -- 09:51:35 - <Info> -- Fetching https://rules.emergingthreats.net/open/suricata-6.0.10/emerging.rules.tar.gz.
 100% - 3893087/3893087               
19/5/2023 -- 09:51:37 - <Info> -- Done.





# From there, we may "start" suricata : 

    $ sudo service suricata start
    

    $ sudo service suricata status


 # The below is when we first start zeekctl, check for errors, thereafter zeek may only "start". The "deploy function" allows us to put things into place after a "configuration change".   


    $ sudo zeekctl deploy 



┌──(root㉿kali)-[/home/kali]

└─# sudo zeekctl status         

Name         Type       Host          Status    Pid    Started

zeek         standalone localhost     running   21191  19 May 09:40:21


  
# We'll allow filebeat to run : 

     $ sudo service filebeat start
    
    
  $ sudo service filebeat status 

─# sudo service filebeat status 
● filebeat.service - Filebeat sends log files to Logstash or directly to Elasticsearch.
     Loaded: loaded (/lib/systemd/system/filebeat.service; disabled; preset: disabled)
     Active: active (running) since Fri 2023-05-19 09:44:10 EDT; 1h 3min ago
       Docs: https://www.elastic.co/beats/filebeat
   Main PID: 23287 (filebeat)
      Tasks: 8 (limit: 8215)
     Memory: 41.8M
        CPU: 2.972s
     CGroup: /system.slice/filebeat.service
             └─23287 /usr/share/filebeat/bin/filebeat --environment systemd -c /etc/filebeat/filebeat.yml --path.ho>

May 19 10:43:13 kali filebeat[23287]: 2023-05-19T10:43:13.538-0400        INFO        [monitoring]        log/log.g>
May 19 10:43:43 kali filebeat[23287]: 2023-05-19T10:43:43.538-0400        INFO        [monitoring]        log/log.g>
May 19 10:44:13 kali filebeat[23287]: 2023-05-19T10:44:13.539-0400        INFO        [monitoring]        log/log.g>
May 19 10:44:43 kali filebeat[23287]: 2023-05-19T10:44:43.543-0400        INFO        [monitoring]        log/log.g>
May 19 10:45:03 kali filebeat[23287]: 2023-05-19T10:45:03.526-0400        INFO        [add_docker_metadata]        >
May 19 10:45:13 kali filebeat[23287]: 2023-05-19T10:45:13.544-0400        INFO        [monitoring]        log/log.g>
May 19 10:45:43 kali filebeat[23287]: 2023-05-19T10:45:43.539-0400        INFO        [monitoring]        log/log.g>
May 19 10:46:13 kali filebeat[23287]: 2023-05-19T10:46:13.545-0400        INFO        [monitoring]        log/log.g>
May 19 10:46:43 kali filebeat[23287]: 2023-05-19T10:46:43.538-0400        INFO        [monitoring]        log/log.g>
May 19 10:47:13 kali filebeat[23287]: 2023-05-19T10:47:13.537-0400        INFO        [monitoring]        log/log.g>
lines 1-21/21 (END)


# Hooray , we've made it, the filebeat pipeline is working fine and active. 

# Let's get this to run and move on to our "elastic deployment" and start observing the "logs", however most importantly, we will ensure if the "data", is moving into "Elastic", using a "Pcap" application. 




                                                                              *************//////// Installing TCPReplay - Testing IDS - Sending Logs to Elastic Search ///////******************


# Since we'll need to capture and review the logs of the network packet-capture, "Pcap", as they go into the Elastic. 


- Install TCPReplay :

┌──(root㉿kali)-[/home/kali]
└─
# sudo apt install tcpreplay -y 
  
  Reading package lists... Done
  Building dependency tree... Done
Reading state information... Done
tcpreplay is already the newest version (4.4.3-1).
The following packages were automatically installed and are no longer required:
  bluez-firmware debugedit dh-elpa-helper docutils-common figlet finger firebird3.0-common firebird3.0-common-doc
  firmware-ath9k-htc firmware-atheros firmware-brcm80211 firmware-intel-sound firmware-iwlwifi firmware-libertas
  firmware-realtek firmware-sof-signed firmware-ti-connectivity firmware-zd1211 freerdp2-x11 gdal-data



# In case we would need to analyse large amount of data flowing into the ElasticSearch : 




- Below is a proposed, "bigflows.pcap", which we may test out. 


  $ wget https://s3.amazonaws.com/tcpreplay-pcap-files/bigflows.pcap  



# Let's try this packet capture application known as "tcpreplay" : 



- Here are some of their abbrev : 


# -t : Makes it go as fast as it can through the interface.

# -v : Outputs Verbose on the screen, such that we may see the IP Address. 

# -i : allows you to enter down the interface, in our case this would be the sniffing interface, eth1.
 


# Given that, our sniffing interface is "eth1",, this would start ingesting the packets into "kabana" for visualizations. As a quick advice, loop in small amount of packets, to avoid "packet loss". 


  $ sudo  tcpreplay -t -v -i eth1 yashil.pcap 





- Remaining work in Progress/ Expansion of this Project : 

# This is the end of this tutorial, at some point in time, we may need to implement some isualization techniques, like "kibana". This may be reproduced, inside of a home or office network, in which a span-port within a "Managed switch, can be used to intercept internet traffic into a virtual network , which would then be monitored by zeek/suricata traffic into Elastic Search vice-versa and visualized on "Kibana or Splunk".






          ***********//// Visualizations Purposes - SIEM Kibana Auditbeat *********///


# ElasticSearch is a "NOSQL Database" which provides advanced analytics, which allows for "machine learning" jobs as well as setting alerts.




# Download the public signing key : 

- We'll first begin with the "import of the Elastic PGP Key"  which is used to sign all of the packages : 



    $ wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -




# Since most of the packages are hailing from a "common repository", we want to ensure that the right communication is being used, when downloading the required "packages"  : 


┌──(root㉿kali)-[/home/kali/Desktop]                                            

└─# sudo apt-get install apt-transport-https                                    

Reading package lists... Done                                                   
Building dependency tree... Done                                                
Reading state information... Done                                               
apt-transport-https is already the newest version (2.6.0).                      



- Let's save the "new repo" to the repository location inside of the "/etc/apt/sources.list.d" dirsectory :


┌──(root㉿kali)-[/home/kali/Desktop]

└─# echo "deb https://artifacts.elastic.co/packages/oss-7.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-7.x.list


deb https://artifacts.elastic.co/packages/7.x/apt stable main
                                                                       



  # we'll now be installing the "ElasticSearch Debian" Package : 


    $ apt-get update && sudo apt-get install elasticsearch
        
Err:4 https://download.docker.com/linux/ubuntu kali-rolling Release                                                 
  404  Not Found [IP: 13.226.139.110 443]                                                                           
Get:5 http://kali.download/kali kali-rolling/main amd64 Packages [19.3 MB]                                          
Get:6 http://kali.download/kali kali-rolling/main amd64 Contents (deb) [44.7 MB]                                    
Reading package lists... Done                                                                                      
E: The repository 'https://download.docker.com/linux/ubuntu kali-rolling Release' does not have a Release file.     
N: Updating from such a repository can't be done securely, and is therefore disabled by default.                    
N: See apt-secure(8) manpage for repository creation and user configuration details.                                
W: https://artifacts.elastic.co/packages/7.x/apt/dists/stable/InRelease: Key is stored in legacy trusted.gpg keyring
 (/etc/apt/trusted.gpg), see the DEPRECATION section in apt-key(8) for details.                                     
                                                                                                                    

┌──(root㉿kali)-[/home/kali/Desktop]                     

└─# apt install elasticsearch -y                                                                            

Reading package lists... Done                                                          
Building dependency tree... Done                                                
Reading state information... Done                                                      
The following packages were automatically installed and are no longer required:         
  bluez-firmware debugedit dh-elpa-helper docutils-common figlet finger firebird3.0-common firebird3.0-common-doc   
  firmware-ath9k-htc firmware-atheros firmware-brcm80211 firmware-intel-sound firmware-iwlwifi firmware-libertas    
  firmware-realtek firmware-sof-signed firmware-ti-connectivity firmware-zd1211 freerdp2-x11 gdal-data              
  gdal-plugins kali-linux-firmware libaec0 libarmadillo11 libarpack2 libblosc1 libbson-1.0-0 libcfitsio10           
  libcfitsio9 libfbclient2 libfreerdp-client2-2 libfreerdp2-2 libfreexl1 libfsverity0 libfyba0 libgeos-c1v5 




# Let us start the "service elasticsearch", which will boot up the "server", and beware that this process will take up a lot of ressources.(in terms of RAM) : 


┌──(root㉿kali)-[/etc/apt/sources.list.d]

└─# service elasticsearch start  




- Let's check that the service is "up" and "running" : 



  $ service elasticsearch status


┌──(root㉿kali)-[/etc/apt/sources.list.d]

└─# service elasticsearch status  

● elasticsearch.service - Elasticsearch
     Loaded: loaded (/lib/systemd/system/elasticsearch.service; disabled; preset: disabled)
     Active: active (running) since Sun 2023-05-21 12:02:58 EDT; 14min ago
       Docs: https://www.elastic.co
 
 
 
 >>>> # Here is the process ID :  Main PID: 620492 (java)
 
 
      Tasks: 60 (limit: 8215)
     Memory: 3.7G
        CPU: 1min 38.743s
     CGroup: /system.slice/elasticsearch.service
             ├─620492 /usr/share/elasticsearch/jdk/bin/java -Xshare:auto -Des.networkaddress.cache.ttl=60 -Des.ne>
             └─620764 /usr/share/elasticsearch/modules/x-pack-ml/platform/linux-x86_64/bin/controller

May 21 12:02:08 kali systemd[1]: Starting elasticsearch.service - Elasticsearch...
May 21 12:02:58 kali systemd[1]: Started elasticsearch.service - Elasticsearch.



# Here's a "second way" to test if the elastic search is working, we'll "curl the loopback address" of the "elastic stack" 

  $ curl 127.0.0.1:9200


  ┌──(root㉿kali)-[/etc/apt/sources.list.d]

└─# curl 127.0.0.1:9200                     
{
  "name" : "kali",
  "cluster_name" : "elasticsearch",
 
 >>>  "cluster_uuid" : "LQXHtWawQTiOrCpfJBQjPQ",
 
 >>> "version" : {
 
    "number" : "7.17.10",
    "build_flavor" : "default",
    "build_type" : "deb",
    "build_hash" : "fecd68e3150eda0c307ab9a9d7557f5d5fd71349",
    "build_date" : "2023-04-23T05:33:18.138275597Z",
    "build_snapshot" : false,
    "lucene_version" : "8.11.1",
    "minimum_wire_compatibility_version" : "6.8.0",
    "minimum_index_compatibility_version" : "6.0.0-beta1"
  },
  "tagline" : "You Know, for Search"
}
                                          

# We would need to stop the Elastic Stack Server prior to implementing, "Winlog Beat", such that it ingests traffic from our "Windows Host Machine" and sends this across to our "Elasticsearch Stack Server" for advanced analytics.




- Let's go ahead and restart the "Elastic Server" : 



  $ sudo service elasticsearch stop 



# We'll now do some "configuration changes" which will allow us to ingests traffic from the outside world.(Target Host Machine : Windows) 


┌──(root㉿kali)-[/etc/apt/sources.list.d]

└─# sudo nano /etc/elasticsearch/elasticsearch.yml 



# Within this document, we'll be modifying and affecting "Network Host"  as well as the "discovery.seed_hosts" : 


- Hint : Watch out for the legends, >>>>, for further explanation.



# ---------------------------------- Network -----------------------------------
#
# By default Elasticsearch is only accessible on localhost. Set a different
# address here to expose this node on the network:
#

>>>>> Make sure to adjust the "IP Address" to that of the Kali Machine, Guest Machine, 'Bridge Adapater" 

>>>> network.host: 192.168.2.18


#
# By default Elasticsearch listens for HTTP traffic on the first free port it
# finds starting at 9200. Set a specific HTTP port here:
#
#http.port: 9200
#
# For more information, consult the network module documentation.
#
# --------------------------------- Discovery ----------------------------------
#
# Pass an initial list of hosts to perform discovery when this node is started:
# The default list of hosts is ["127.0.0.1", "[::1]"]
#



>>>>  # Under the "discovery.seed_hosts, there would be typically, one of which will be a "master node" and the other node will be a "slave node". 
>>>>>>>>> In our case, we will keep a single "Master Node".


discovery.seed_hosts: ["192.168.2.18"]
#
# Bootstrap the cluster using an initial set of master-eligible nodes:
#
#cluster.initial_master_nodes: ["node-1", "node-2"]
#
# For more information, consult the discovery and cluster formation module documentation.




  # Once this has been modified, ensure that this has been saved. 




   # Starting the "ElasticSearch Server" ; 
  

      $ sudo service elasticsearch restart




- Let's continue to test out the Windows Machine, if it can initiate "communication" with the "ElasticSearch Stack" at port 9200. 


# From Command Prompt : 

- Run this command : 

C:\WINDOWS\system32>curl 192.168.2.18:9200
{
  "name" : "kali",
  "cluster_name" : "elasticsearch",
  "cluster_uuid" : "LQXHtWawQTiOrCpfJBQjPQ",
  "version" : {
    "number" : "7.17.10",
    "build_flavor" : "default",
    "build_type" : "deb",
    "build_hash" : "fecd68e3150eda0c307ab9a9d7557f5d5fd71349",
    "build_date" : "2023-04-23T05:33:18.138275597Z",
    "build_snapshot" : false,
    "lucene_version" : "8.11.1",
    "minimum_wire_compatibility_version" : "6.8.0",
    "minimum_index_compatibility_version" : "6.0.0-beta1"
  },
  "tagline" : "You Know, for Search"
}




> # Installation of Kibana

> [!TIP]
>  Given that we do not have the "kibana repository" under the "offical Kali Linux repo", we'll then be downloading and extracting "kibana.**tar.gz" file under https://www.elastic.co /downloads/kibana. 
 
  
  $ sudo apt install kibana  -y 


```
┌──(root㉿kali)-[/home/kali]

└─# apt install kibana  -y 


Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
Package kibana is not available, but is referred to by another package.
This may mean that the package is missing, has been obsoleted, or
is only available from another source

E: Package 'kibana' has no installation candidate
                                                     

- In order to download the kibana file, we will make use of the "wget" command : 
```

root㉿kali)-[/opt]

└─# wget https://artifacts.elastic.co/downloads/kibana/kibana-8.7.1-amd64.deb

--2023-05-22 11:43:29--  https://artifacts.elastic.co/downloads/kibana/kibana-8.7.1-amd64.deb
Resolving artifacts.elastic.co (artifacts.elastic.co)... 34.120.127.130, 2600:1901:0:1d7::
Connecting to artifacts.elastic.co (artifacts.elastic.co)|34.120.127.130|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 239590498 (228M) [binary/octet-stream]



# Afterwards we'll then use the "dpkg" command, and run the file : 


┌──(root㉿kali)-[/opt]

└─# ls 

49757.py                 discover                      Investigation                         pstree.txt                velociraptor-docker
506332.txt               dive_0.9.2_linux_amd64.deb    kibana-8.7.1-amd64.deb                RedEye                    virlutils
63740.txt                dnscat2                       knock                                 slurp                     volatility3
blackeye-im              dump-endpoints.jq             microsoft                             Spiderpig                 WmiEvent
bucket-stream            EyeWitness                    mysql-apt-config_0.8.22-1_all.deb     sslScrape                 ZAP_2_10_0_unix.sh
censys-subdomain-finder  github.com                    ngrok                                 suricata_rules            zaproxy
core.23335               grr-server_3.4.0-1_amd64.deb  openapi-spec.json                     VBoxGuestAdditions-7.0.6  zeek
DataSurgeon              httpscreenshot                phantomjs-1.9.8-linux-x86_64.tar.bz2  velociraptor              zeek-docker
                                                                                                                                                           
┌──(root㉿kali)-[/opt]

└─# ls -larh | grep kibana  

-rw-r--r--  1 root         root         229M May  2 05:38 kibana-8.7.1-amd64.deb



# Running the "Kibana" installation : 



┌──(root㉿kali)-[/opt]

└─# dpkg -i kibana-8.7.1-amd64.deb 

Selecting previously unselected package kibana.
(Reading database ... 472166 files and directories currently installed.)
Preparing to unpack kibana-8.7.1-amd64.deb ...
Unpacking kibana (8.7.1) ...





                  ***********//// Installing our "AuditBeat" : Sends log and signals/information to ElasticStack *****////


# Beat is a key component, specifically is "Lightweight agent" which will allow us to monitor the Linux servers in the cloud and on-site ( for e.g, Windows Machine).



- Let's get this beast installed : 


┌──(root㉿kali)-[/opt]             

└─# sudo apt install auditbeat -y  
s
Reading package lists... Done                                                
Building dependency tree... Done
Reading state information... Done                                            
The following packages were automatically installed and are no longer required:
  bluez-firmware debugedit dh-elpa-helper docutils-common figlet finger firebird3.0-common firebird3.0-common-doc firmware-ath9k-htc firmware-atheros
  firmware-brcm80211 firmware-intel-sound firmware-iwlwifi firmware-libertas firmware-realtek firmware-sof-signed firmware-ti-connectivity
  firmware-zd1211 freerdp2-x11 gdal-data gdal-plugins kali-linux-firmware libaec0 libarmadillo11 libarpack2 libblosc1 libbson-1.0-0 libcfitsio10
  libcfitsio9 libfbclient2 libfreerdp-client2-2 libfreerdp2-2 libfreexl1 libfsverity0 libfyba0 libgeos-c1v5 libgeos3.11.1 libgeotiff5 libhashkit2
  libhdf4-0-alt libhdf5-103-1 libhdf5-hl-100 libkmlbase1 libkmldom1 libkmlengine1 libmemcached11 libmongoc-1.0-0 libmongocrypt0 libmpdec3 libnetcdf19
  libnginx-mod-http-geoip libnginx-mod-http-image-filter libnginx-mod-http-xslt-filter libnginx-mod-mail libnginx-mod-stream libnginx-mod-stream-geoip
  libodbc2 libodbcinst2 libogdi4.1 libpoppler123 libproj25 libprotobuf23 libpython3.10 libpython3.10-dev libpython3.10-minimal libpython3.10-stdlib
  librpmbuild9 librpmsign9 librttopo1 libspatialite7 libsuperlu5 libsz2 libtiff5 liburiparser1 libwinpr2-2 libxerces-c3.2 libzxingcore1
  linux-image-6.0.0-kali3-amd64 medusa nginx-core php8.1-mysql proj-bin proj-data python-odf-doc python-odf-tools python-pastedeploy-tpl
  python-tables-data python3-aioredis python3-ajpy python3-alabaster python3-apscheduler python3-bottleneck python3-commonmark python3-docutils
  python3-git python3-gitdb python3-imagesize python3-ipy python3-numexpr python3-odf python3-pandas python3-pandas-lib python3-pyexploitdb
  python3-pyfiglet python3-pyshodan python3-pysmi python3-pysnmp4 python3-quamash python3-roman python3-smmap python3-snowballstemmer python3-speaklater
  python3-sphinx python3-tables python3-tables-lib python3-tld python3-yaswfp python3.10 python3.10-dev python3.10-minimal rpm ruby3.0 ruby3.0-dev
  ruby3.0-doc rwho rwhod sparta-scripts sphinx-common toilet-fonts unixodbc-common wapiti
Use 'sudo apt autoremove' to remove them.
The following NEW packages will be installed:
  auditbeat




                              **********//// Configuring Auditbeat + Kibana ******////// 


# Great we've both "Auditbeat and  Kibana" installed, we will now groom(send the logs to our ElasticSearch Stack) them and get them to start : 


  $ sudo nano  /etc/kibana/kibana.yml`



 /etc/kibana/kibana yml                                                                
# For more configuration options see the configuration guide for Kibana in
# https://www.elastic.co/guide/index.html

# =================== System: Kibana Server ===================
# Kibana is served by a back end server. This setting specifies the port to use.
#server.port: 5601

# Specifies the address to which the Kibana server will bind. IP addresses and host names are both valid values.
# The default is 'localhost', which usually means remote machines will not be able to connect.
# To allow connections from remote users, set this parameter to a non-loopback address.

>>>>>>>>>
>>>>>>>>>>>>>>>>  We could have modified the "server.host", such that it reflects the "IP address" of our Kali linux, "bridge Adapter IP" : 192.168.2.18
>>>>>>>>>>>>
>>>>>
#server.host: "localhost"


  
# The maximum payload size in bytes for incoming server requests.
#server.maxPayload: 1048576

# The Kibana server's name. This is used for display purposes.
#server.name: "your-hostname"

# =================== System: Kibana Server (Optional) ===================
# Enables SSL and paths to the PEM-format SSL certificate and SSL key files, respectively.
# These settings enable SSL for outgoing requests from the Kibana server to the browser.
#server.ssl.enabled: false
#server.ssl.certificate: /path/to/your/server.crt
#server.ssl.key: /path/to/your/server.key

# =================== System: Elasticsearch ===================
# The URLs of the Elasticsearch instances to use for all your queries.


>>>
>>>>> We'll now modify the "elasticsearch.hosts" and set this to, "https://192.168.2.18:9200",and ensure to remove the #, "hash key" to apply the changes. 
>>>>>>>>
elasticsearch.hosts: ["http://192.168.2.18:9200"]

# If your Elasticsearch is protected with basic authentication, these settings provide
# the username and password that the Kibana server uses to perform maintenance on the Kibana
# index at startup. Your Kibana users still need to authenticate with Elasticsearch, which
# is proxied through the Kibana server.
#elasticsearch.username: "kibana_system"
#elasticsearch.password: "pass"





> # Configuring the AuditBeat + Module auditd



- As a brief explanation, "auditd module" provides a high level "monitoring logging" on the targetted "kernel operating system".(for e.g windows/Linux)


  # We'll now configure the "lightweight AuditBeat" : 



  $  sudo nano /etc/auditbeat/auditbeat.yml




                        /etc/auditbeat/auditbeat.yml                                                             

###################### Auditbeat Configuration Example #########################

# This is an example configuration file highlighting only the most common
# options. The auditbeat.reference.yml file from the same directory contains all
# the supported options with more comments. You can use it as a reference.
#
# You can find the full configuration reference here:
# https://www.elastic.co/guide/en/beats/auditbeat/index.html

# =========================== Modules configuration ============================
auditbeat.modules:

- module: auditd
  # Load audit rules from separate files. Same format as audit.rules(7).
  audit_rule_files: [ '${path.config}/audit.rules.d/*.conf' ]
  audit_rules: |
    ## Define audit rules here.
    ## Create file watches (-w) or syscall audits (-a or -A). Uncomment these
    ## examples or add your own rules.

    ## If you are on a 64 bit platform, everything should be running
    ## in 64 bit mode. This rule will detect any use of the 32 bit syscalls
    ## because this might be a sign of someone exploiting a hole in the 32
    ## bit API.
    #-a always,exit -F arch=b32 -S all -F key=32bit-abi

    ## Executions.
    #-a always,exit -F arch=b64 -S execve,execveat -k exec

    ## External access (warning: these can be expensive to audit).
    #-a always,exit -F arch=b64 -S accept,bind,connect -F key=external-access

    ## Identity changes.




>>>> #  The below module will actively check for the file integrity at these "file system paths", to avoid attacks : 
>>>>>>>>
>>>>>

- module: file_integrity
  paths:
  - /bin
  - /usr/bin
  - /sbin
  - /usr/sbin
  - /etc


>>>>>>>
>>>>> The module below will go over the "datasets" in each of the instances, for e.g, host, login, package, process... etc : 
>>> The module "system", was not included in this file, so we've just added it.

- module: system
datasets: 

- host	# General host information, e.g. uptime, IPs
- login # User logins,logouts and system boots. 
- package # Installed, updated, and removed packages.
- process # Started and stopped processes
- socket # Opened and closed sockets
- user # User information



# Add in the setting below to perform "regular checks on the datasets" mentioned above : 


>>>>>>> state.period: 1m 



  # Let's now test the "auditbeat configuration" : 


  $ sudo auditbeat test config



# Let's test with the "output" command, in order to check the communication between auditbeat and the "ElasticSearch Server"  : 

┌──(root㉿kali)-[/etc/kibana/certs]

└─# sudo auditbeat test output     

elasticsearch: http://192.168.2.18:9200...
  parse url... OK
  connection...
    parse host... OK
    dns lookup... OK
    addresses: 192.168.2.18
    dial up... OK
  TLS... WARN secure connection disabled
  talk to server... OK
  version: 7.9.2

# At times, if "elasticsearch server" has not loaded yet, we may obtain an "error" ;  dial up... ERROR dial tcp 192.168.2.18:9200: connect: connection refused. 





# Let's enable and start the "auditbeat" service : 

  $ systemctl enable  --now  auditbeat




Furthermore, we'll quickly be going over the "Kibana Section" : 


# =================================== Kibana ===================================

# Starting with Beats version 6.0.0, the dashboards are loaded via the Kibana API.
# This requires a Kibana endpoint configuration.
setup.kibana:

  # Kibana Host
  # Scheme and port can be left out and will be set to the default (http and 5601)
  # In case you specify and additional path, the scheme is required: http://localhost:5601/path
  # IPv6 addresses should always be defined as: https://[2001:db8::1]:5601


>>>>>>>>>
>>>>>> We'll be keeping the host information below as it is at "localhost:5601", so nothing to be changed here. 

>>>>>
  #host: "localhost:5601"

  # Kibana Space ID
  # ID of the Kibana Space into which the dashboards should be loaded. By default,
  # the Default Space will be used.
  #space.id:



- Next section, "Elastic Cloud", since we're not using any "elastic cloud providers", so we will not undergo any changes. 



# =============================== Elastic Cloud ================================

# These settings simplify using Auditbeat with the Elastic Cloud (https://cloud.elastic.co/).

# The cloud.id setting overwrites the `output.elasticsearch.hosts` and
# `setup.kibana.host` options.
# You can find the `cloud.id` in the Elastic Cloud web UI.
#cloud.id:

# The cloud.auth setting overwrites the `output.elasticsearch.username` and
# `output.elasticsearch.password` settings. The format is `<user>:<pass>`.
#cloud.auth:





# The "Outputs Section" is the most important one, where we'll bring some changes :



                 *******////    Outputs Section : Change the Localhost to our Elastic Server, IP Address   ////*******

 ================================== Outputs ===================================

# Configure what output to use when sending the data collected by the beat.

# ---------------------------- Elasticsearch Output ----------------------------
output.elasticsearch:
  # Array of hosts to connect to.




>>>>>>> 
# Please modify the below, otherwise by default, `auditbeat` is set to send the "logs" to our "ElasticSearch" at the `localhost`, instead make sure to change it to the "IP Address" of our "Elastic Server", `192.168.2.18`. 
>>>>>>
>>>>>>>>
>>>>>
>>>
# Here is where we'll be modifying our hosts: ["localhost:9200"] >>>>> hosts: ["192.168.2.18:9200"]
 


  # Protocol - either `http` (default) or `https`.
  #protocol: "https"

  # Authentication credentials - either API key or username/password.
  #api_key: "id:api_key"
  #username: "elastic"
  #password: "changeme"







# Another Section : Beats allows us to other sort of Outputs, such as the "Logstash Output", and use the "kafka Server"  instead of the ElasticSearch Server : 


# ------------------------------ Logstash Output -------------------------------
#output.logstash:
  # The Logstash hosts
  #hosts: ["localhost:5044"]

  # Optional SSL. By default is off.
  # List of root certificates for HTTPS server verifications
  #ssl.certificate_authorities: ["/etc/pki/root/ca.pem"]

  # Certificate for SSL client authentication
  #ssl.certificate: "/etc/pki/client/cert.pem"

  # Client Certificate Key
  #ssl.key: "/etc/pki/client/cert.key"





                      *********//////  Start the Services UP - Auditbeat + Kibana  *********////// 


# Finally we've been able to configure both of the services, let's now work on starting both up : 


# Start kibana : 

  $ sudo service kibana start




- ElasticSearch provides us with amazing tooling right "out of the box", like, "loaded templates", dashboards, kibana and many more, but it's as much important to have this "fully setup".   


# Very important : Make sure to have the "default templates", indexes loaded, "dashboards and kibana" ready prior to starting "auditbeat". 



# Let's render this command below, such that we can "examine the logs" outputted to the console, which will give us "confidence" that it can connect to the "ElasticSearch server Stack".



- e  : logs to our console 

- setup : setup command 



# Let's get this going, and just so you're aware this will produce a "series of log events" :  


  $ sudo auditbeat -e setup


2023-05-22T13:40:06.183-0400    INFO    instance/beat.go:698    Home path: [/usr/share/auditbeat] Config path: [/etc/auditbeat] Data path: [/var/lib/auditb
eat] Logs path: [/var/log/auditbeat] Hostfs Path: [/]                                                                                                      
2023-05-22T13:40:06.197-0400    INFO    instance/beat.go:706    Beat ID: e68758c6-798e-4329-8ef5-33017a1c862b
2023-05-22T13:40:09.202-0400    WARN    [add_cloud_metadata]    add_cloud_metadata/provider_aws_ec2.go:79       read token request for getting IMDSv2 token
 returns empty: Put "http://169.254.169.254/latest/api/token": context deadline exceeded (Client.Timeout exceeded while awaiting headers). No token in the 
metadata request will be used.                                                                                                                             
2023-05-22T13:40:09.393-0400    INFO    [beat]  instance/beat.go:1052   Beat info       {"system_info": {"beat": {"path": {"config": "/etc/auditbeat", "dat
a": "/var/lib/auditbeat", "home": "/usr/share/auditbeat", "logs": "/var/log/auditbeat"}, "type": "auditbeat", "uuid": "e68758c6-798e-4329-8ef5-33017a1c862b"}}}                                                                                                                                                       
2023-05-22T13:40:09.393-0400    INFO    [beat]  instance/beat.go:1061   Build info      {"system_info": {"build": {"commit": "78a342312954e587301b653093954
ff7ee4d4f2b", "libbeat": "7.17.10", "time": "2023-04-23T08:09:56.000Z", "version": "7.17.10"}}}
2023-05-22T13:40:09.393-0400    INFO    [beat]  instance/beat.go:1064   Go runtime info {"system_info": {"go": {"os":"linux","arch":




# Refer to the logs below , as a "Proof of Concept", that it is indeed connecting and running the required templates, as well as making a "connection" to our elasticsearch Server. 



Overwriting ILM policy is disabled. Set `setup.ilm.overwrite: true` for enabling.                                                                                       
                                          
2023-05-22T13:40:09.952-0400    INFO    [index-management]      idxmgmt/std.go:260      Auto ILM enable success.                                              
2023-05-22T13:40:10.421-0400    INFO    [index-management.ilm]  ilm/std.go:180  ILM policy auditbeat successfully 
created.                                              



# Template, index, patterns, graphs, kibana dashboards being loaded : 

2023-05-22T13:40:10.421-0400    INFO    [index-management]      idxmgmt/std.go:396      Set setup.template.name to '{auditbeat-7.17.10 {now/d}-000001}' as ILM is enabled.
2023-05-22T13:40:10.421-0400    INFO    [index-management]      idxmgmt/std.go:401      Set setup.template.pattern to 'auditbeat-7.17.10-*' as ILM is enabled.          
2023-05-22T13:40:10.421-0400    INFO    [index-management]      idxmgmt/std.go:435      Set settings.index.lifecycle.rollover_alias in template to {auditbeat-7.17.10 {now/d}-000001} as ILM is enabled.
2023-05-22T13:40:10.421-0400    INFO    [index-management]      idxmgmt/std.go:439      Set settings.index.lifecycle.name in template to {auditbeat {"policy":{"phases":{"hot":{"actions":{"rollover":{"max_age":"30d","max_size":"50gb"}}}}}}} as ILM is enabled.
2023-05-22T13:40:10.433-0400    INFO    template/load.go:197    Existing template will be overwritten, as overwrite is enabled.




# Connection being made >>>>> 2023-05-22T13:40:10.703-0400    INFO    template/load.go:131    Try loading template auditbeat-7.17.10 to Elasticsearch



2023-05-22T13:40:11.387-0400    INFO    template/load.go:123    Template with name "auditbeat-7.17.10" loaded.
2023-05-22T13:40:11.388-0400    INFO    [index-management]      idxmgmt/std.go:296      Loaded index template.                                                         
2023-05-22T13:40:12.206-0400    INFO    [add_cloud_metadata]    add_cloud_metadata/add_cloud_metadata.go:101    add_cloud_metadata: hosting provider type not detected.
2023-05-22T13:40:12.661-0400    INFO    [index-management.ilm]  ilm/std.go:140  Index Alias auditbeat-7.17.10 successfully created.                                                                                                                                                                                                       
Index setup finished.                                                               



# Let's enable auditbeat : 


  $ sudo systemctl  enable  --now auditbeat


┌──(root㉿kali)-[/etc/elasticsearch]

└─# systemctl enable --now auditbeat        

Synchronizing state of auditbeat.service with SysV service script with /lib/systemd/systemd-sysv-install.
Executing: /lib/systemd/systemd-sysv-install enable auditbeat
Created symlink /etc/systemd/system/multi-user.target.wants/auditbeat.service → /lib/systemd/system/auditbeat.service.
                                                                                                                                


# Start "auditbeat" : 


┌──(root㉿kali)-[/opt]

└─# service auditbeat start 


┌──(root㉿kali)-[/opt]

└─# netstat -talpn                            

Active Internet connections (servers and established)

Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    

tcp        0      0 127.0.0.1:36893         0.0.0.0:*               LISTEN      866/containerd      
tcp        0      0 127.0.0.1:8889          0.0.0.0:*               LISTEN      1019/velociraptor.b 
tcp        0      0 127.0.0.1:8001          0.0.0.0:*               LISTEN      1019/velociraptor.b 
tcp        0      0 127.0.0.1:8003          0.0.0.0:*               LISTEN      1019/velociraptor.b 
tcp        0      1 192.168.2.18:36078      169.254.169.254:80      SYN_SENT    92001/auditbeat     
tcp        0      0 127.0.0.1:8001          127.0.0.1:59676         ESTABLISHED 1019/velociraptor.b 
tcp        0      0 127.0.0.1:59676         127.0.0.1:8001          ESTABLISHED 1019/velociraptor.b 

 >>>>>  tcp6       0      0 192.168.2.18:9300       :::*                    LISTEN      7774/java           
tcp6       0      0 :::8000                 :::*                    LISTEN      1019/velociraptor.b 

 >>>>> tcp6       0      0 192.168.2.18:9200       :::*                    LISTEN      7774/java           


# As we try to connect to the Kibana, at this address location http://localhost:5601, this is constantly rendering the same error, "Kibana Server not ready yet."



                       ///////// ****** Persistent Ongoing Workaround + Log Analysis  ***************//////////  

# Let's analyze the logs at this directory : /var/log/kibana

- Check the "logs being outputted", when the "kibana service" is being restarted.

  - Try any of these "commands", for any "pertinent issues" related to "firewall", "incompatibility".


# Let's start to dig through the logs : 

  $ journalctl  --unit kibana


May 22 23:32:35 kali kibana[310957]: [2023-05-22T23:32:35.551-04:00][INFO ][plugins-service] Plugin "cloudChat" is disabled.
May 22 23:32:35 kali kibana[310957]: [2023-05-22T23:32:35.551-04:00][INFO ][plugins-service] Plugin "cloudExperiments" is disabled.
May 22 23:32:35 kali kibana[310957]: [2023-05-22T23:32:35.551-04:00][INFO ][plugins-service] Plugin "cloudFullStory" is disabled.
May 22 23:32:35 kali kibana[310957]: [2023-05-22T23:32:35.551-04:00][INFO ][plugins-service] Plugin "cloudGainsight" is disabled.
May 22 23:32:35 kali kibana[310957]: [2023-05-22T23:32:35.559-04:00][INFO ][plugins-service] Plugin "profiling" is disabled.
May 22 23:32:36 kali kibana[310957]: [2023-05-22T23:32:35.927-04:00][INFO ][http.server.Preboot] http server running at http://localhost:5601








  # We've also made some changes to the file, "/etc/kbana/kibana.yml" : 


# =================== System: Elasticsearch ===================
# The URLs of the Elasticsearch instances to use for all your queries.


>>>>>elasticsearch.hosts: ["http://192.168.2.18:9200"]

# If your Elasticsearch is protected with basic authentication, these settings provide
# the username and password that the Kibana server uses to perform maintenance on the Kibana
# index at startup. Your Kibana users still need to authenticate with Elasticsearch, which
# is proxied through the Kibana server.


>>>>>>>
>>>>>>>>>
# These are the "newly added" or "uncommented"settings needed for "kibana" to run properly : 
>>>>>>elasticsearch.username: "kibana_system"
>>>>elasticsearch.password: "pass"



# =================== System: Elasticsearch (Optional) ===================
# These files are used to verify the identity of Kibana to Elasticsearch and are required when


>>>> xpack.security.enabled : true

# xpack.security.http.ssl.client_authentication in Elasticsearch is set to required.
#elasticsearch.ssl.certificate: /path/to/your/client.crt
#elasticsearch.ssl.key: /path/to/your/client.key
#xpack.encryptedSavedObjects.encryptionKey: "rG*3H&1a#vY8p$9aK5mY2sI7zQ6xX4c"



      
      
- Restart Kibana for the changes to take effect : 


    $ service kibana restart 



# Restart AuditBeat : 

  $ sudo service auditbeat restart




# Re-run the auditBeat setup : 

  $ sudo auditbeat -e setup  



# As a good practice, after each and every changes, verify that "kibana works fine" while connecting to the URL : http://localhost:5601




              ****////// Incompatibility Issues - Kibana 8.7 + ElasticSearch 7.17 (No Match) ********/////


# It is of utmost importance, that the version for "Kibana and Elasticsearch" matches, in our situation this should work both at "version 7.17"


  
  
  - Proceed with the "uninstallation" of the Previous Version of Kibana : 



 $ apt remove kibana




# Try the following, in case you would need to remove the "elasticsearch" to match the right version or reinstall the firmware upto a "factory reset" :  




# First step shut down the engine : 


  $ service elasticsearch stop


# Start removing the "gpg key", from this path location : 


┌──(root㉿kali)-[/usr/share/keyrings]                                                                                                                                         
└─

# rm -rf elasticsearch-keyring.gpg              





- Below is the "Common installation path" for "ElasticSearch" : 


  $  sudo apt remove elasticsearch 


- Make sure to delete each indivildual directory :


# Installation Directory : 


     $ sudo rm -rf /usr/share/elasticsearch

     $  sudo rm -rf /usr/local/elasticsearch


# Path.data Directory : 

     $ sudo rm -rf /var/lib/elasticsearch  


     $ sudo rm -rf /var/lib/elasticsearch 



# Path.logs Directory :

     $ sudo rm -rf /var/log/elasticsearch


# Elastic Configuration files  :


    $ sudo rm -rf /etc/elasticsearch


# Remove ElasticSearch "User and Group" :

   $ sudo deluser elasticsearch

   $ sudo delgroup elasticsearch




