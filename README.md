
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

> - Uncomment the "#port 22", and update this to "port number to 65328" : 


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



# ***Continue Setup and IDS with FileBeat***


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


> -  ***From here, let's add in some of the lines accordingly (check the pointers below)***_ : 

```
* # management interface

* ---> allow-hotplug eth0
* ---> iface eth0 inet dhcp

* # sniffing interface
* ----> allow-hotplug eth1
* ----> iface eth1 inet manual
* ---> up ifconfig eth1 prmisc up
* --> down ifconfig  eth1 promisc down
}

``

# In this tutorial, we've created two "network interfaces", one of them is under a NAT Network, whilst the other one is a "HOST-Only Network(constrained network), private address for our Kali Linux Machine" 


Here are our "Network interface cards : 


- eth0 : NAT Interface Card

- eth1 : Host-Only Interface Card 


- In our case, here's the equivalent of the "Network Interface File" for our "Kali OS" : 


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


# Note : For Ubuntu User's we're trying to stop the "systemd-networkd", which is a network panner service. 
- For Kali Users no need to worry about this. 





- Let's proceed with stopping this service : 

# From the Ubuntu command-Line Terminal : 


  $ sudo service systemd-networkd stop



# Again for our Ubuntu Users, we will use another command to ensure complete removal, of the "netplan service" : 


  $ sudo apt remove netplan -y 




# ***Installing Suricata - Signature Based IDS***



 # For this tuturial, we have two options, however, we shall start with the "easiest one", first one as the second one requires us to "build and compile the file from source". 



- Run this command to install "Suricata Stable",Version from its "repository" : 


    $  sudo apt install software-properties-common



# Installation of Suricata : 


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



# Option 2 : 



#  To begin with, we grabbed a ".gz version" of "Suricata Signature-Based-IDS", we're good to extract the following : 

  
  - Extracting the file, suricata-6.0.11.tar.gz


    $ tar xzf suricata-6.0.11.tar.gz



──(root㉿kali)-[/suricata-Signature-Based-IDS]

└─# ls

suricata-6.0.11  suricata-6.0.11.tar.gz


- Let's head into the directory suricata-6.0.11


# Run the following command to generate the "MakeFile" : 



   $ ./configure 


# Build "Suricata", using the "make" commmand : 


  $ make install



# Some Encountered issues on the way : 

- As we try to run our update on our Kali Machine, we happen to experience that the URL's, for e,g , "www.kali.org" is not resolving to anything. 



- Next we tried to update our "sources.list" at this directory, 


    $ sudo nano /etc/apt/sources.list



# Let's add these 2 lines onto our file : 

deb http://us.archive.kali.org/kali kali-rolling main non-free contrib
deb-src http://us.archive.kali.org/kali kali-rolling main non-free contrib


We'll now update the entire machine with this command :


  $ apt update
 

┌──(root㉿kali)-[/home/kali]
└─# apt update             

Ign:1 https://download.greenbone.net/apt/gb-stable/20.08 main/ InRelease                                   

Ign:2 http://http.kali.org/kali kali-rolling InRelease                                                     

Ign:3 http://us.archive.kali.org/kali kali-rolling InRelease        

Ign:3 http://us.archive.kali.org/kali kali-rolling 
InRelease                                               

Ign:1 https://download.greenbone.net/apt/gb-stable/20.08 main/ InRelease                                   

Ign:2 http://http.kali.org/kali kali-rolling InRelease   


# We're still stuck at the InReleae step .. 





- Let's check our DNS Resolution with this command, right before let`s take a look at another command  : 


# This would allow us to add in the "network interface", "Ip Addrress, and all other related information : 

$ sudo nmtui  



# From the below, we can clearly see that our DNS Server is halting us : 


┌──(root㉿kali)-[/etc]

└─# nslookup 192.168.243.1

;; communications error to 192.168.243.1#53: timed out



# Our next step will involve adding a namserver(Google DNS) in addition to our "Local DNS Server" (192.168.243.XX) to our directory, "/etc/resolv.conf". 


nameserver 8.8.8.8
nameserver 8.8.4.4      



# Make sure that the "newly added", "nameservers" stays into the "resolv.conf", as this may occasionally, gets erased by itself after a booting process. 


- From the below, just replace the <nameserver_IP> with the IP Address, of the nameserver 8.8.8.8 and 8.8.4.4 


Let's each one by one : 

echo "nameserver <nameserver_IP>" | sudo tee -a /etc/resolvconf/resolv.conf.d/head



echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolvconf/resolv.conf.d/head

echo "nameserver 8.8.4.4" | sudo tee -a /etc/resolvconf/resolv.conf.d/head



---------------------------------------------------------------------------------------------------------------------



# Run the command to update the resolv.conf  :

  $ sudo resolv.conf -u 
# We may need to install the resolvconf through apt : 

  $ apt-get install resolvconf  


# Lastly, we'll nmow clear the apt cache, in case this is causing any sort of conflict  : 


  $ apt clean




                                                                                                                                    *********//////// Configuring Suricata Yaml  ///////////*********







# In order to configure the "Suricata Yaml" file, let's make use of any editor and access the file at "/etc/suricata/suricata.yaml" : 


    $ mousepad /etc/suricata/suricata.yaml 

# Once we're in there, make sure to replace the default interface, to your previously "assigned sniffing interface : eth0 " shown in the directory , "/etc/network/interfaces"




# Note that the "HOME_NET network " has CIDR belonging to the "HOST-Only Network" with interface card eth1. 


- Also consider naming your network as "HOME_NET", and search the "suricata.yaml" file, for its corresponding "#HOME_NET" IP address.
- (Don't uncomment these HOME_NET)






#  For the `sake of clarity`, we've hve included the `interface file("/etc/network/interface")` below, so that you may `distinguish` between the `"sniffing interface and the management interface"`. 



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


# Change the following lines, within the "suricata.yaml file" and also add in the "Sniffing NIC Address, Network Address , eth1", as well as addding a corresponding "Subnet Mask, /24"



Let us start modifying and adding these information as required at the following location ; /etc/suricata/suricata.yaml



# Remember to change the interface from eth0 --> eth1


- Below we intentionally, added a new "HOME_NET" Address which matches that of our "Host-Only Network", in addition we also "uncommented" it, as follows, HOME_NET:"[192.168.233.0/24]" : 


vars:
  # more specific is better for alert accuracy and performance
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    #HOME_NET: "[192.168.0.0/16]"
    #HOME_NET: "[10.0.0.0/8]"
    #HOME_NET: "[172.16.0.0/12]"
    #HOME_NET: "any"
    
  # Add in this line correspondoing to our actual `Home_Network` --->>>   HOME_NET:"[192.168.233.0/24]"
    


# Note :  Make sure to change/disable, "chechsum validation : No", and the reason for this, is we want to avoid "rejecting or dropping off packets", in case if the "packet capture" software being used, oversees the captured packets not passing the "checksum validation."



# Stream engine settings. Here the TCP stream tracking and reassembly 
# engine is configured.
#
# stream:
#   memcap: 64mb                # Can be specified in kb, mb, gb.  Just a
#                               # number indicates it's in bytes.
#   memcap-policy: ignore       # Can be "drop-flow", "pass-flow", "bypass",
#                               # "drop-packet", "pass-packet", "reject" or
#                               # "ignore" default is "ignore"

# ---->> Change this setting to `no` #   checksum-validation: yes/ = `no`    # To validate the checksum of received









                                                                                                                ********///////// Creating a "Service File for Suricata(Start or Stop, for e.g service ssh start) *********//////////// 





# Great, we're good to use to Suricata, however, we would need to use "command-line arguments", to get this to start each and every time(rather lengthy and cumbersome)

s
# Remember ; In our case the new `Release`,already contains an added service file, for `Suricata`. 



# We'll head to the directory below and start to create "suricata.service" file :  


  $ sudo nano /lib/systemd/system/suricata.service


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



# Under the current Version of Suricata, there seem to be a similar version of what we have gone through above (almost the same) : 

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





      

      
                                                                                                                                  *********////// Zeek Installation(Including Compilation : Building from Source) //////*******




# Zeek is a good monitoring tool which provide a "rich parsing of packet metadata", for e.g, "understanding what a protocol is doing and what commands are being sent."



- First of all, we will be installing some "dependencies" , thereafter, we''ll then be building this from `source` (compilationl)


# Let's ensure that "Git" is installed on our Machine : 


┌──(root㉿kali)-[/home/kali]

└─# apt-get install git -y 

Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
git is already the newest version (1:2.39.2-1.1).
The following packages were automatically installed and are no longer required:
  catfish dh-elpa-helper docutils-common gir1.2-xfconf-0
  libcfitsio9 libgdal31 libmpdec3 libnginx-mod-http-geoip
  libnginx-mod-http-image-filter libnginx-mod-http-xslt-filter
  libnginx-mod-mail libnginx-mod-stream libnginx-mod-stream-geoip
  libpoppler123 libprotobuf23 libpython3.10 libpython3.10-dev
  libpython3.10-minimal libpython3.10-stdlib libtiff5
  libzxingcore1 nginx-common nginx-core python-pastedeploy-tpl
  python3-alabaster python3-commonmark python3-docutils
  python3-imagesize python3-roman python3-snowballstemmer
  python3-speaklater python3-sphinx python3.10 python3.10-dev
  python3.10-minimal ruby3.0 ruby3.0-dev ruby3.0-doc
  sphinx-common

Use 'sudo apt autoremove' to remove them.

0 upgraded, 0 newly installed, 0 to remove and 321 not upgraded.


# We have couple of things we would need while building, "Zeek from source", here are the development packaages : 

- cmake 
- make 
- gcc  
- g++ 
- flex  
- bison 
- libpcap-dev
- libssl-dev

* --> - python-dev **

- swig  

* --> - zliblg-dev ** 


# However for these 2 development packages,(python3-dev, zliblg-dev) did not work as expected could be that they 're obsoleete.Let's check if there may be any alternatives. 


- Check if there're any python development that matches our need : 




    $ sudo apt-cache search python dev 
                                                                    
acr - autoconf like tool                                                                                                                                
astro-development - C/C++ development packages for astronomy                                                                                            
autoimport - Automatically import missing Python libraries                                                                                              
autoradio - radio automation software                                                                                                                   
b4 - helper utility to work with patches made available via a public-inbox archive                                                                      
berrynet-dashboard - deep learning gateway - python3 modules                                                                                            
blag - Blog-aware, static site generator                                                                                                                
blag-doc - Blog-aware, static site generator (documentation)                                                                                            
bluefish - advanced Gtk+ text editor for web and software development                                                                                   
brltty - Access software for a blind person using a braille display                                                                                     
budgie-dropby-applet - Applet to popup when a USB device is connected                                                                                   
bugz - command-line interface to Bugzilla                                                                                                               
capirca-docs - Multi-platform ACL generation system (documentation)                                                                                     
cloud-sptheme-common - Cloud Sphinx theme and related extensions (theme files and docs)                                                                 
clustershell - Distributed shell that provides an efficient Python interface                                                                            
collectd-core - statistics collection and monitoring daemon (core system)                                                                               
commix - Automated All-in-One OS Command Injection and Exploitation Tool                                                                                
confy - Conference schedule viewer written in Python                                                                                                    
debmake-doc - Guide for Debian Maintainers                                                                                                              
debomatic - automatic build machine for Debian source packages                                                                                          
deluge-gtk - bittorrent client written in Python/PyGTK (GTK+ ui)                    



# Let's install the missing dev-packages : 



┌──(root㉿kali)-[/home/kali]                                                


      $ sudo apt-get install python3-dev

                                                

                                                                                                                    
Reading package lists... Done                                                                                                                           
Building dependency tree... Done                                                                                                                        
Reading state information... Done                                           
The following packages were automatically installed and are no longer required:                                                                         
  catfish dh-elpa-helper docutils-common gir1.2-xfconf-0 libcfitsio9 libgdal31 libmpdec3 libnginx-mod-http-geoip libnginx-mod-http-image-filter         
  libnginx-mod-http-xslt-filter libnginx-mod-mail libnginx-mod-stream libnginx-mod-stream-geoip libpoppler123 libprotobuf23 libpython3.10
  libpython3.10-dev libpython3.10-minimal libpython3.10-stdlib libtiff5 libzxingcore1 nginx-common nginx-core python-pastedeploy-tpl python3-alabaster
  python3-commonmark python3-docutils python3-imagesize python3-roman python3-snowballstemmer python3-speaklater python3-sphinx python3.10              
  python3.10-dev python3.10-minimal ruby3.0 ruby3.0-dev ruby3.0-doc sphinx-common                                        




# The last missing part of the puzzle, "zliblg-dev" : 


┌──(root㉿kali)-[/usr/local]

└─# apt-cache  search zlib1g-dev 

zlib1g-dev - compression library - development

r-bioc-zlibbioc - (Virtual) zlibbioc Bioconductor package
                                                              


┌──(root㉿kali)-[/usr/local]

└─# apt-get install zlib1g-dev  

Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
zlib1g-dev is already the newest version (1:1.2.13.dfsg-1).
The following packages were automatically installed and are no longer required:
  python3-aardwolf python3-aesedb python3-aiocmd python3-aioconsole python3-aiosmb
  python3-aiowinreg python3-arc4 python3-asciitree python3-asn1tools python3-asyauth
  python3-asysocks python3-bitstruct python3-cryptography37 python3-diskcache python3-lsassy
  python3-masky python3-minidump python3-minikerberos python3-msldap python3-neo4j python3-neobolt
  python3-neotime python3-oscrypto python3-pylnk3 python3-pypsrp python3-pypykatz
  python3-pywerview python3-spnego python3-unicrypto python3-winacl python3-xmltodict
Use 'sudo apt autoremove' to remove them.
0 upgraded, 0 newly installed, 0 to remove and 101 not upgraded.





 # After a `"series of enquiries"` with regards to `"why" some of the dependencies are not going through, found an "Alternative Source"` for the `right dependencies` : 



┌──(root㉿kali)-[/usr/local]

└─# sudo apt-get install cmake make gcc g++ flex libfl-dev bison libpcap-dev libssl-dev python3 python3-dev swig zlib1g-dev


Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
cmake is already the newest version (3.27.4-1).
make is already the newest version (4.3-4.1).
gcc is already the newest version (4:13.2.0-1).
g++ is already the newest version (4:13.2.0-1).
flex is already the newest version (2.6.4-8.2).
libfl-dev is already the newest version (2.6.4-8.2).
bison is already the newest version (2:3.8.2+dfsg-1+b1).
libpcap-dev is already the newest version (1.10.4-4).
libssl-dev is already the newest version (3.0.10-1).
python3 is already the newest version (3.11.4-5+b1).
python3-dev is already the newest version (3.11.4-5+b1).
swig is already the newest version (4.1.0-0.3).
zlib1g-dev is already the newest version (1:1.2.13.dfsg-1).
The following packages were automatically installed and are no longer required:
  python3-aardwolf python3-aesedb python3-aiocmd python3-aioconsole python3-aiosmb python3-aiowinreg python3-arc4 python3-asciitree
  python3-asn1tools python3-asyauth python3-asysocks python3-bitstruct python3-cryptography37 python3-diskcache python3-lsassy
  python3-masky python3-minidump python3-minikerberos python3-msldap python3-neo4j python3-neobolt python3-neotime python3-oscrypto
  python3-pylnk3 python3-pypsrp python3-pypykatz python3-pywerview python3-spnego python3-unicrypto python3-winacl python3-xmltodict
Use 'sudo apt autoremove' to remove them.
0 upgraded, 0 newly installed, 0 to remove and 101 not upgraded.






- Here're the description of what each of this mean : 


# Dependencies : 

- cmake make gcc g++ flex libfl-dev bison ; Has to do with compiling and building. 

- libpcap-dev libssl-dev python3 python3-dev swig zlib1g-dev ;  Development dependencies needed to build software, and "packat captures" development packages. 
 


# We'll now proceed to the installation of Zeek from its "Git Repository" : 


    

┌──(root㉿kali)-[/opt]

└─# git clone --recursive  https://github.com/zeek/zeek

Cloning into 'zeek'...
remote: Enumerating objects: 226988, done.
remote: Counting objects: 100% (317/317), done.
remote: Compressing objects: 100% (161/161), done.
remote: Total 226988 (delta 189), reused 231 (delta 150), pack-reused 226671
Receiving objects: 100% (226988/226988), 165.40 MiB | 3.79 MiB/s, done.









# Note : Applying the --recursive option to our git clone command, allows us to include all the child "files and folders" within this "current Repo" to be cloned, to avoid missing out on important files while cloning. 



Let's create a directory called, /NIDS and "mv" Zeek to this "specified" directory. 


┌──(root㉿kali)-[/NIDS]

└─# cd zeek 
                                                                                                                                                        
                                                                                                                                                               
┌──(root㉿kali)-[/opt/zeek]

└─# ls  

auxil    ci     CMakeLists.txt   configure  COPYING-3rdparty  docker   Makefile  NEWS    README.md  src      vcpkg.json  zeek-path-dev.in
CHANGES  cmake  cmake_templates  COPYING    doc               INSTALL  man       README  scripts    testing  VERSION



# We're now good to `build "Zeek"`, from `source`. 



           



                                                  
                                                                                                                                                          *******////////  Important Rules to Compilation - C++/C - Memorize ********/////////





# Whenever we've the need to `build`, or `compile builds` from `scratch/source`, such that to `create a binary executable`, then please follow along : 



- Go after the directory of the application/source file we want to compile : 

# Classic 3 of instructions, make sure to run this at the "root privilege" : 




1. ./configure : Checks if all the `dependencies are there`, and what their `location` are required to be. 


# From this step, make sure to read through each line as soon as the command "./configure" is launched, as the latter may help us to "debug" in case of any error. 


# Case Scenario : During execution, we may encounter some errors due to missing dependencies or most probably that the author forgot to point out a "dependency" or while versioning, something has changed.(work around this, using chatgpt)



# Run  ./configure : 

Build Directory : build                                                                                                                
Source Directory: /NIDS/zeek                                                                                                           
Using cmake version 3.25.1                                                                                                             
                                                                                                                                       
-- The C compiler identification is GNU 12.2.0                                                                                         
-- The CXX compiler identification is GNU 12.2.0                                                                                       
-- Detecting C compiler ABI info                                                                                                       
-- Detecting C compiler ABI info - done                                                                                                
-- Check for working C compiler: /usr/bin/cc - skipped                                                                                 
-- Detecting C compile features                                                                                                        
-- Detecting C compile features - done                                                                                                 
-- Detecting CXX compiler ABI info                                                                                                     
-- Detecting CXX compiler ABI info - done                                                                                              
-- Check for working CXX compiler: /usr/bin/c++ - skipped                                                                              
-- Detecting CXX compile features                                                                                                      
-- Detecting CXX compile features - done                                                                                               
-- Performing Test test_arch_x64                                                                                                       
-- Performing Test test_arch_x64 - Success                                                                                             
-- Performing Test test_arch_aarch64                                                                                                   
-- Performing Test test_arch_aarch64 - Failed                    




                


                                                                                                                                *********/////  Second Step - 2. "make" commamd + Changing ScreenTImeout/Kali + Keep-alive Message DropBear Server Modification  ******/////////




# Lenthiest process, considering the "Size of the Processor", "RAM Size", and this is where the actual "compilation" takes place. 


# Important : Prior to running the "make command" for its compilation process, make sure to adjust the "ScreenTimeout" together with the "Keep-Alive Default Server message", in order to prevent any eventual disruption while "compiling". 


- Let's now run the "make" command : 



┌──(root㉿kali)-[/opt/zeek]                                                                                                                     

└─# make                                                                                                                                        

make -C build all                                                                                                                               
make[1]: Entering directory '/opt/zeek/build'                                                                                                   
make[2]: Entering directory '/opt/zeek/build'                                                                                                   
make[3]: Entering directory '/opt/zeek/build'                                                                                                   
[  0%] [BISON][BIFParser] Building parser with bison 3.8.2                                                                                      
[  0%] [FLEX][BIFScanner] Building scanner with flex 2.6.4                                                                                      
make[3]: Leaving directory '/opt/zeek/build'                                                                                                    
make[3]: Entering directory '/opt/zeek/build'                                                                                                   
[  0%] Building CXX object auxil/bifcl/CMakeFiles/bifcl.dir/bif_parse.cc.o                                                                      
[  0%] Building CXX object auxil/bifcl/CMakeFiles/bifcl.dir/bif_lex.cc.o      


# After the "compilation process" has successfully ended, we will then proceed to the very last par below.


                                    
                                    
                                    
                                    
                                                                                                                                                            ********///////// Altering the ScreenTimeout to never  ////////********




# Note :  Since this will be taking a lot of time, from Settings --> "power management" --> ScreenTimeout set to "Never" to prevent the screen from timeing out during the "compilation" process.








                                                                                                                                                  ********////////// Changing the Keep-Alive Default message to 300 Seconds //////////********




#  For convenience purposes, we want to resume our entire work at any point in time on "Windows, Command Prompt", using our Server as the only Option. 


 - Configure DropBear Server's Keep-Alive, by heading to its "configuration file", "/etc/default/dropbear". 


# From there, add in the "option" to "bypass" its "Default Keep-Alive" and set this to 300 seconds instead of 60 Seconds.





# Within the Configuration file : 


{
# The TCP port that Dropbear listens on
#DROPBEAR_PORT=22
# NO_START=0
# Receive window size - this is a tradeoff between memory and network performance
#DROPBEAR_RECEIVE_WINDOW=65536

# Any additional arguments for Dropbear.  For instead set
#
#   DROPBEAR_EXTRA_ARGS="-b /etc/issue.net"
#
# to specify an optional banner file containing a message to be sent to
# clients before they connect; or
#
#   DROPBEAR_EXTRA_ARGS="-r /etc/dropbear/rsa_host_key -r /etc/dropbear/ed25519_host_key"

* Add this line* -->   #   DROPBEAR_OPTIONS="-s -g -k 300"

# to specify custom host keys.  See dropbear(8) for possible values.
#DROPBEAR_EXTRA_ARGS=""
} 




# Then restart the DropBear Service : 


    $ service dropbear restart
       



  # Run the "make command" : 

  
┌──(root㉿kali)-[/NIDS/zeek]                                       
       
        
    $   make 


make -C build all                                                                                                                      
make[1]: Entering directory '/NIDS/zeek/build'                     
make[2]: Entering directory '/NIDS/zeek/build'             
make[3]: Entering directory '/NIDS/zeek/build'                     
[  0%] [BISON][BIFParser] Building parser with bison 3.8.2         
[  0%] [FLEX][BIFScanner] Building scanner with flex 2.6.4         
make[3]: Leaving directory '/NIDS/zeek/build'                                                                                          
make[3]: Entering directory '/NIDS/zeek/build'                     
[  0%] Building CXX object auxil/bifcl/CMakeFiles/bifcl.dir/bif_parse.cc.o                                                             
[  0%] Building CXX object auxil/bifcl/CMakeFiles/bifcl.dir/bif_lex.cc.o                                                               
[  0%] Building CXX object auxil/bifcl/CMakeFiles/bifcl.dir/bif_arg.cc.o                                                               
[  0%] Building CXX object auxil/bifcl/CMakeFiles/bifcl.dir/module_util.cc.o                                                           
[  0%] Linking CXX executable bifcl                                
make[3]: Leaving directory '/NIDS/zeek/build'                      
[  0%] Built target bifcl                                                               


# Warning : This can take really long, 12 hours or more. 





# In some cases the `compilation process` may `fail` asnd due to the fact that this was `taking way too long`, therefore, we `interrupted the compilation process` and right after, we tried the `make` command again : 


- Re-run the compilation as follows : 


    $ make clean 
    

# We'll run the "compilation process" once more : 

    $ make 


# Tips : Some Easy Steps to upgrade your Machine Ram Size : 


- Check in the Total Ram Size in the Slot : 

C:\Users\YashCyb>systeminfo | findstr /C:"Total Physical Memory"
Total Physical Memory:     16,301 MB


# Get the maximum Ram Size : 

C:\Users\YashCyb>wmic memphysical get maxcapacityEx
MaxCapacityEx

33554432 --> 32 Gb




                                                                                                                                        ********/////////// 3. sudo make install - Last Part (Actual Installation) *******////////////




# Now, we're good to engage and `install our application` after the `compilation` has been `completed`s. 


      $ sudo make install


Great !!, we 're good to go .. 

              
                          
                          
                          

      
      
                                                                                                                                    ********/////////// 4. Configuring Zeek after installation(Adding Zeek to our "Path") ////////*********



# Here is the last step, that will allow us to call on "Zeek within the Terminal" and this will be usually done through "/etc" environment file. 


- The suggested "command for Ubuntu" and similarly this seem to work for our "Linux Distribution" to allow for this necessary change, here it is as follows : 



# Add in the following "path" for "zeek" : "/usr/local/zeek/bin"

 
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




# Add Zeek path to your `system's PATH environmental variable` by adding the following line, `export PATH=$PATH:/usr/local/go/bin` to our `path, "~/.zhsrc, ~/.bashrc"`. 



──(root㉿kali)-[/usr/local/zeek/bin]
└─# nano ~/.zshrc
                                                                                                                                                                                           
┌──(root㉿kali)-[/usr/local/zeek/bin]
└─# nano ~/.bashrc



************************                                                                                             
                                                                                             
# PATH EXPORT                                                                                
                                                                                             
export PATH=$PATH:/usr/local/zeek/bin
                                              
**********************************



# By adding "export PATH", to "~/.zshrc, ~/.bashrc", allows us to run `Zeek`, without the need to `enter Zeek's full location path` .
     

- Let's access these two location from our "Linux Terminal" and add the corresponding "export PATH" : 


      $ nano ~/.bashrc 


      $ nano /.zshrc

# Then add the  "export PATH=$PATH:/usr/local/go/bin" to the very end of  "/.zshrc && /.bashrc" .. 





                                        *******///////// Configuration of Zeek files - Specifying the IP ranges + Node + (zeek)Control  ******///////////



# These are the 3 files which we would need to modify : 


┌──(root㉿kali)-[/usr/local/zeek/etc]

└─# ls 

networks.cfg  node.cfg  zeekctl.cfg  zkg
                                              

# We'll mow start to configure the network configuration for "zeek" at this location ; "nano /usr/loca/zeek/etc/networks.cfg" 

                                            

- See what the "file" network.cfg looks like ;


                                                                                                
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


# Take notice of how we've added, the 192.168.2.0/24(unhash, without the #) , and this corresponds to our "HOME_NET" under Suricata which is our default "Network Address of eth0 : 192.168.2.0/24"

 





# Now we'll be haeding to the configuration of the "zeek node" itself :


- Let's proceed to this path itself and modify, the "Sniffing Interface" : 



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



# Our "last file" is to setup "zeekctl.cfg" which is the zeek control orchestration "application", it controls event of logging, amd control "clusters".


- Let's make our way to the following location  : /usr/local/zeek/etc/zeekctl.cfg 





# Mail connection summary reports each log rotation interval.  A value of 1
# means mail connection summaries, and a value of 0 means do not mail
# connection summaries.  This option has no effect if the trace-summary
# script is not available.

* ---> Set to "0",  MailConnectionSummary = 1 / "0"

# Lower threshold (in percentage of disk space) for space available on the
# disk that holds SpoolDir. If less space is available, "zeekctl cron" starts
# sending out warning emails.  A value of 0 disables this feature.

* ...> Set to "0", MinDiskSpace = 5 / "0"

# Send mail when "zeekctl cron" notices the availability of a host in the
# cluster to have changed.  A value of 1 means send mail when a host status
# changes, and a value of 0 means do not send mail.


* ---> Set to "0", MailHostUpDown = 1 /"0"




# will be deleted by "zeekctl cron".  The interval is an integer followed by
# one of these time units:  day, hr, min.  A value of 0 means that logs
# never expire.

* ....> Set to "1 day", LogExpireInterval = 0 / "1 day"


# means write to stats.log, and a value of 0 means do not write to stats.log.

* >>>> Set this to "0" StatsLogEnable = 1 / "0"


# that entries never expire.
>>>> Set this to "1" StatsLogExpireInterval = 0 / "1"



Finally let's head to where we'll be "archiving" each rotation interval within the same document :



# Make sure this has been set to the below directory, otherwise "filebeat" may have some difficulties in recuperating those : 


LogDir = /var/log/zeek/logs


# Save everything after the applied changes. 





                                          
                                          
                                                           *********/////// Create ZeekCtl Cron job //////***********



# ZeekCtl would require crontab to setup "Log Rotation" activities ....


Just to summarize, our "cronjob", will be as follows : 





# Our cronjob will run every 5 mins, log rotation : 

# m h  dom mon dow   command  Argument

*/5 * * * *  /usr/local/zeek/bin/zeekctl cron 


# Let's access our "Crontab" , and in the "new cronjob" : 


    $ crontab -e 


- Select our default interpreter, chose "1" for nano, and our file will look as in the below : 



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






                                  *********//////// Change Configuration Output Format of the logs to Json - Policy Tuning /////////*******





   #  Interestingly, we would want to change the "configuration output format" of the logs to "JSON" : 


     $  sudo  nano /usr/local/zeek/share/zeek/site/local.zeek




#  We will go at the very "bottom" of the page, and search through and alter as well as add in the line below : 



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



* >>>>>  # Uncomment the following line to enable logging of link-layer addresses. Enabling

# this adds the link-layer address for each connection endpoint to the conn.log file.
# @load policy/protocols/conn/mac-logging



* ---- >>>> This is where we'd add the line : 

# Output to JSON
@load policy/tuning/json-logs.zeek 


# Uncomment this to source zkg's package state
# @load packages

}


# Basically, these "added line", would tell the "zeekctl", to log into a file directory that doesn't yet exist ..So let's create a directory as the very last step .. 




- Let's make sure to create the "directory, called zeek" at the following location, "/var/log"



┌──(root㉿kali)-[/var/log]

└─# mkdir zeek                                               



# We shall now "cd" into the directory : 


┌──(root㉿kali)-[/var/log]

└─# cd zeek      



# Now within the directory,"zeek", let us now have another directory created called, "logs" : 


┌──(root㉿kali)-[/var/log/zeek]  

  $ mkdir  -p logs 

┌──(root㉿kali)-[/var/log/zeek]
└─# ls 

logs



# Our, file logging location would be at this new directory, "/var/logs/zeek/logs"

┌──(root㉿kali)-[/logs]

└─# cd /var/log/zeek/logs  






                                              **********/////////// FileBeat Agent Installation + Signing Key Download  + Add Elastic Stable Repository  + Add apt-transport-https  /////////////*********




# Filebeat is an "agent" which will be in "charge of taking our logs" and place them into "elastic search" for "visualization purposes"(Kibana).  




- To start off, we will be downloading its "signing key" :



# Here is the signing key installation which is in "GPG" :


- GNU Privacy Guard, better known as GnuPG or just GPG, is an implementation of "public key cryptography".



 ┌──(root㉿kali)-[/var/log/zeek/logs]

└─#  wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add - 

Warning: apt-key is deprecated. Manage keyring files in trusted.gpg.d instead (see apt-key(8)).
OK




                      *************/// Add the repository from "stable main" ///******************


- Our next step, is to add the "repository" from the "elastic stable" branch: 


# Add the repo, but prior to that, make sure to install the packaga for "https transport" as this allows encryption and authentication over https : 



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




                      *************//////// Configuring the filebeat Configuration File **********//////////



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





                              ************/// Installation of Kibana ////***************

# Let's try the below command, however, this would not work, as we don't have the "kibana repository" under the "offical Kali Linux repo". 

  
  $ sudo apt install kibana  -y 



┌──(root㉿kali)-[/home/kali]
└─# apt install kibana  -y 


Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
Package kibana is not available, but is referred to by another package.
This may mean that the package is missing, has been obsoleted, or
is only available from another source

E: Package 'kibana' has no installation candidate
                                                     


# Instead, we will be downloading and extracting "kibana.**tar.gz" file under https://www.elastic.co /downloads/kibana. 



- In order to download the kibana file, we will make use of the "wget" command : 


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





                              ***************//// Configuring the AuditBeat + Module auditd ************//////////




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





                      ********///// Adding an extra layer of Security, "Sysmon and WinlogBeat" to our Host Machine (Windows) //////********



# Today in this very tutorial, we'll be adding "logging service" to our Local Host Machine.(Windows)


# **** Sysmon being part of the "sysinternals software package" monitors dll's, processes, connections, network connections, basically is a standalone tool that enriches the amount of data, threats that we may "detect". 


- Let's begin with the installation of Sysmon/Sysinternals : 


# Just download "Sysmon" from the following URL : 

  - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon


- Extract the "Sysmon.zip" files at this location : 

C:\Program Files\Sysmon


# Run the "Sysmon" file, "Sysmon64.exe" 



- We'll also need to have a "sample configuration file", in order to work with "Sysmon", here is the "repo" ;


The configuration file can be found here : https://github.com/SwiftOnSecurity/sysmon-config


# Remember : There exists, a lot of configuration for data enhancement, like Mitre Attack Techniques, take a look at the available forks on the repo.






#  Git clone the "repo" at this location :  C:\Program Files> 

      
      
    $ git clone https://github.com/SwiftOnSecurity/sysmon-config





# From the location path below, "C:\Program Files\sysmon-config" drag and drop the "sysconfig-export-xml" into the following "Sysmon" directory, C:\Program Files\Sysmon : 

C:\Program Files\sysmon-config> dir

 Directory of C:\Program Files\sysmon-config

26/05/2023  16:28    <DIR>          .
26/05/2023  16:28    <DIR>          ..
26/05/2023  16:28                83 .gitignore
26/05/2023  16:28             3,357 README.md
26/05/2023  16:28           123,257 sysmonconfig-export.xml
               3 File(s)        126,697 bytes
               2 Dir(s)  73,052,303,360 bytes free



# After dropping the sysconfig-export-xml, your "sysmon" directory, should be similar to this : 



 Directory of C:\Program Files\Sysmon> dir

26/05/2023  16:40    <DIR>          .
26/05/2023  16:40    <DIR>          ..
12/04/2023  22:14             7,490 Eula.txt
12/04/2023  22:15         8,228,608 Sysmon.exe
12/04/2023  22:15         4,443,392 Sysmon64.exe
12/04/2023  22:15         4,785,408 Sysmon64a.exe

>>>>>> 26/05/2023  16:28           123,257 sysmonconfig-export.xml




                *******///// Installing Sysmon service(services.msc) ////// ************


 - We would now install "Sysmon" service, and this will show on "services.msc"


# Next up, we should rename the "sysconfig-export.xml", as "sysmonconfig.xml", and while using "command prompt", we'll then navigate to directory path, "C:\Program files\sysmon" and install 



# From Command Prompt run the below command : 


# -i : Installation
# -accepteula : Accepting terms and condition
# -l : Image loads
# -n : network monitoring, DNS
# -h : hash, sha256 


 >>>>> PS C:\Program Files\Sysmon> .\Sysmon.exe -i sysmonconfig.xml -accepteula -h sha256 -l -n




 # In case you may have previously installed `Sysmon`, `force uninstall` it `prior` to the `re-installation`, using the below `command` : 


PS C:\Program Files\Sysmon> .\Sysmon.exe -u force



System Monitor v15.14 - System activity monitor
By Mark Russinovich and Thomas Garnier
Copyright (C) 2014-2024 Microsoft Corporation
Using libxml2. libxml2 is Copyright (C) 1998-2012 Daniel Veillard. All Rights Reserved.
Sysinternals - www.sysinternals.com

# Stopping SysmonDrv......................................................................


# Note : Despite `forcing the unistallation of the Sysmon using the above command `, the `SysmonDrv.sys` still exists .. 




# Found an `interesting script` which uninstall the `Sysmon from the following location` : 


1. "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon64",
2. "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv",
3. "HKLM:\SYSTEM\ControlSet001\Services\Sysmon64",
4. "HKLM:\SYSTEM\ControlSet001\Services\SysmonDrv",
5. "HKLM:\SYSTEM\ControlSet002\Services\Sysmon64",
6. "HKLM:\SYSTEM\ControlSet002\Services\SysmonDrv",
7. "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational",
8. "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
9. "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Microsoft-Windows-Sysmon-Operational"





# Below shows the `powershell script` which allows for the `deletion of core Sysmon components` (make sure to run the script with `Admin Privilege`using `powershell`) : 

>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

$log_file = 'sysmon-uninstall.log'

$items = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon64",
    "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv",
    "HKLM:\SYSTEM\ControlSet001\Services\Sysmon64",
    "HKLM:\SYSTEM\ControlSet001\Services\SysmonDrv",
    "HKLM:\SYSTEM\ControlSet002\Services\Sysmon64",
    "HKLM:\SYSTEM\ControlSet002\Services\SysmonDrv",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
    "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Microsoft-Windows-Sysmon-Operational"
)

foreach ( $i in $items ) {
    $error.Clear();
    Remove-Item -Path $i -Force -Recurse -ErrorAction SilentlyContinue
    If($error) {
        $result = $error.Exception.Message
    } Else {
        $result = "O : $i"
    }
    Write-Output "$result".ToString() | Out-File -Filepath $log_file -Append -NoClobber -Encoding UTF8
}

>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>


# Very Important Note : For the above `script to take effect`, make sure to stop the `Sysmon service` and `allow for a complete reboot of the workstation`. 





 # Let's `re-run the installtion` using the below command : 

PS C:\Program Files\Sysmon> .\Sysmon.exe -i sysmonconfig.xml -accepteula -h sha256 -l -n


System Monitor v15.14 - System activity monitor
By Mark Russinovich and Thomas Garnier
Copyright (C) 2014-2024 Microsoft Corporation
Using libxml2. libxml2 is Copyright (C) 1998-2012 Daniel Veillard. All Rights Reserved.
Sysinternals - www.sysinternals.com
                                                Loading configuration file with schema version 4.50
Sysmon schema version: 4.90
Warning: Command-line switch 'h' was overwritten by configuration node 'HashAlgorithms' value
Configuration file validated.
Sysmon installed.
SysmonDrv installed.
Starting SysmonDrv.
SysmonDrv started.
Starting Sysmon..
Sysmon started.



# Our `next step` is to ensure that the `Sysmon Service` has `started` :


PS C:\Program Files\Sysmon> Get-service sysmon

Status   Name               DisplayName
------   ----               -----------
Running  Sysmon             sysmon




# Let's check if the `LogEvents` are `showing up` :


PS C:\Program Files\Sysmon> Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10


   ProviderName: Microsoft-Windows-Sysmon

TimeCreated                      Id LevelDispla
                                    yName
-----------                      -- -----------
2/25/2024 10:38:13 PM             8 Information
2/25/2024 10:38:12 PM             8 Information
2/25/2024 10:38:12 PM             1 Information
2/25/2024 10:37:26 PM             8 Information
2/25/2024 10:37:25 PM             8 Information
2/25/2024 10:37:25 PM             1 Information
2/25/2024 10:37:25 PM             1 Information
2/25/2024 10:37:02 PM             1 Information
2/25/2024 10:36:48 PM             1 Information
2/25/2024 10:36:48 PM             1 Information









