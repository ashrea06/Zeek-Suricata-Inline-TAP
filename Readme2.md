


                        *******///// Download WinlogBeat + Installation /////******
                        
# "WinlogBeat" is a key component agent which will ship the "Windows Event Logs" to a Server for further analysis. 



- Download the "WinloBeat file" from the following  : 

 URL : https://www.elastic.co/downloads/beats/winlogbeat





# After having downloaded the file and successfully extracted this, make sure to rename the file "Winlogbeat" : 



 Directory of C:\Users\YashCyb\Downloads

=======

 >>>>>>>>26/05/2023  17:17    <DIR>          winlogbeat-8.8.0-windows-x86_64

13/02/2023  14:43        78,728,232 Wireshark-win64-4.0.3.exe
19/05/2023  21:30             8,062 Yashil Mohadawoo-NetworkAdmin CoverLetter.pdf
19/05/2023  21:52           131,010 Yashil-Mohadawoo.pdf




# After renaming : 
 
 Directory of C:\Users\YashCyb\Downloads

>>>>>>>26/05/2023  17:17    <DIR>          Winlogbeat

13/02/2023  14:43        78,728,232 Wireshark-win64-4.0.3.exe
19/05/2023  21:30             8,062 Yashil Mohadawoo-NetworkAdmin CoverLetter.pdf
19/05/2023  21:52           131,010 Yashil-Mohadawoo.pdf
19/04/2023  10:25           137,600 Zoom_cm_f4sf4Z9vvrZo4_mWYSPqBWJ3OqlGt1iXY0B0wJrPkPd-Vcuu



# Move the file, Winlogbeat to 'C:\Program Files\' : 

C:\Program Files>cd Winlogbeat


# Using Powershell, start the installation of the powershell script, "install-service-winlogbeat.ps1" : 



# Note : Very important, to run this file, the "execution policy" would need to be set at "unrestricted" : 


- Currently, the "execution policy" is set as "restricted", let's change this : 



PS C:\Program Files\Winlogbeat> Get-ExecutionPolicy

Restricted



# Modifying to unrestricted : 


PS C:\Program Files\Winlogbeat> Set-ExecutionPolicy unrestricted



# Let's now run the installation : 


PS C:\Program Files\Winlogbeat> .\install-service-winlogbeat.ps1


Status   Name               DisplayName                           
------   ----               -----------                           
Stopped  winlogbeat         winlogbeat                            



# Check the list of services from "services.msc", and you would see that "Winlogbeat" has been added, however we may want to change the "Startup Type" to "manual". 





                     ******//// Configuring Auditbeat + Kibana + Elasticsearch - Linux Machine  /////****** 


# Our goal is for "WinlogBeat" to ship our "Windows Log Events" to our "Elastic Stack Server" located at the "IP address", 192.168.2.18 (bridged Networking) of our "Linux Machine". 



Let's start to analyze each of the configuration file to be modified : 


1. Kibana.yml



# Kibana is served by a back end server. This setting specifies the port to use.

>>>>>>> server.port: 5601

# Specifies the address to which the Kibana server will bind. IP addresses and host names are both valid values.
# The default is 'localhost', which usually means remote machines will not be able to connect.
# To allow connections from remote users, set this parameter to a non-loopback address.

>>>>>>>>> server.host: "192.168.2.18"

# Enables you to specify a path to mount Kibana at if you are running behind a proxy.
# Use the `server.rewriteBasePath` setting to tell Kibana if it should remove the basePath
# from requests it receives, and to prevent a deprecation warning at startup.
# This setting cannot end in a slash.
#server.basePath: ""

# Specifies whether Kibana should rewrite requests that are prefixed with
# `server.basePath` or require that they are rewritten by your reverse proxy.
# This setting was effectively always `false` before Kibana 6.3 and will
# default to `true` starting in Kibana 7.0.
#server.rewriteBasePath: false

# Specifies the public URL at which Kibana is available for end users. If
# `server.basePath` is configured this URL should end with the same basePath.
#server.publicBaseUrl: ""

# The maximum payload size in bytes for incoming server requests.
#server.maxPayload: 1048576

# The Kibana server's name.  This is used for display purposes.
#server.name: "your-hostname"

# The URLs of the Elasticsearch instances to use for all your queries.


 >>>>>> elasticsearch.hosts: ["http://192.168.2.18:9200"]







2. elasticsearch.yml

# ---------------------------------- Network -----------------------------------
#
# By default Elasticsearch is only accessible on localhost. Set a different
# address here to expose this node on the network:
#

 >>>>>>>network.host: 192.168.2.18
#
# By default Elasticsearch listens for HTTP traffic on the first free port it
# finds starting at 9200. Set a specific HTTP port here:
#
>>>>>>>> #http.port: 9200
#
# For more information, consult the network module documentation.
#
# --------------------------------- Discovery ----------------------------------
#
# Pass an initial list of hosts to perform discovery when this node is started:
# The default list of hosts is ["127.0.0.1", "[::1]"]
#


 >>>>>>>discovery.seed_hosts: ["192.168.2.18"]

#
# Bootstrap the cluster using an initial set of master-eligible nodes:
#
#cluster.initial_master_nodes: ["node-1", "node-2"]
#






3. auditbeat.yml  



# ================================== Outputs ===================================

# Configure what output to use when sending the data collected by the beat.

# ---------------------------- Elasticsearch Output ----------------------------
output.elasticsearch:
  # Array of hosts to connect to.



>>>>>  hosts: ["192.168.2.18:9200"]

  # Protocol - either `http` (default) or `https`.
  #protocol: "https"

  # Authentication credentials - either API key or username/password.
  #api_key: "id:api_key"
  #username: "elastic"
  #password: "changeme"






- All of the "3 configuration file" will most likely stay the same, unless the "IP Address" of our "server.host" has changed. 



# If ever, any changes were brought onto the configuration files, make sure to restart the services. 



    $ service elasticsearch restart

    $ service kibana restart

    $ service auditbeat restart




# In our next step, we will be making some changes on the "winlogbeat.yml" file.




        *******\\\\ Windows - C:\Program Files\Winlogbeat\winlogbeat.yml \\\\******


- From Our "Host Machine", "Windows", let's move to this "path location" where our "winlogbeat.yml" resides : 


# Path Location : C:\Program Files\Winlogbeat\





# =================================== Kibana ===================================

# Starting with Beats version 6.0.0, the dashboards are loaded via the Kibana API.
# This requires a Kibana endpoint configuration.
setup.kibana:

  # Kibana Host
  # Scheme and port can be left out and will be set to the default (http and 5601)
  # In case you specify and additional path, the scheme is required: http://localhost:5601/path
  # IPv6 addresses should always be defined as: https://[2001:db8::1]:5601

>>>>
>>>>> host: "192.168.2.18:5601"
>>>>>>>
  # Kibana Space ID
  # ID of the Kibana Space into which the dashboards should be loaded. By default,
  # the Default Space will be used.
  #space.id:

# =============================== Elastic Cloud ================================

# These settings simplify using Winlogbeat with the Elastic Cloud (https://cloud.elastic.co/).

# The cloud.id setting overwrites the `output.elasticsearch.hosts` and
# `setup.kibana.host` options.
# You can find the `cloud.id` in the Elastic Cloud web UI.
#cloud.id:

# The cloud.auth setting overwrites the `output.elasticsearch.username` and
# `output.elasticsearch.password` settings. The format is `<user>:<pass>`.
#cloud.auth:

# ================================== Outputs ===================================

# Configure what output to use when sending the data collected by the beat.

# ---------------------------- Elasticsearch Output ----------------------------
output.elasticsearch:
  # Array of hosts to connect to.
  
  >>>>>
  >>>>>
  >>>>>>>> hosts: ["192.168.2.18:9200"]

  # Protocol - either `http` (default) or `https`.
  #protocol: "https"

  # Authentication credentials - either API key or username/password.
  #api_key: "id:api_key"
  #username: "elastic"
  #password: "changeme"

  # Pipeline to route events to security, sysmon, or powershell pipelines.
  pipeline: "winlogbeat-%{[agent.version]}-routing"






                    *****/////  Winlogbeat Initialization- StartUp /////*****


# Back to our Host Machine, "windows", from there we would initiate the command below : 


C:\Program Files\Winlogbeat> winlogbeat.exe setup -e

{"log.level":"info","@timestamp":"2023-05-26T18:37:20.451-0400","log.origin":{"file.name":"instance/beat.go","file.
line":779},"message":"Home path: [C:\\Program Files\\Winlogbeat] Config path: [C:\\Program Files\\Winlogbeat] Data path: [C:\\Program Files\\Winlogbeat\\data] Log



 >>>>>> Index setup finished.
Loading dashboards (Kibana must be running and reachable)
{"log.level":"info","@timestamp":"2023-05-28T00:21:59.791-0400","log.logger":"kibana","log.origin":{"file.name":"kibana/client.go","file.line":179},"message":"Kibana url: http://192.168.2.18:5601","service.name":"winlogbeat","ecs.version":"1.6.0"}
{"log.level":"info","@timestamp":"2023-05-28T00:22:00.016-0400","log.logger":"kibana","log.origin":{"file.name":"kibana/client.go","file.line":179},"message":"Kibana url: http://192.168.2.18:5601","service.name":"winlogbeat","ecs.version":"1.6.0"}
{"log.level":"info","@timestamp":"2023-05-28T00:22:10.497-0400","log.origin":{"file.name":"instance/beat.go","file.line":992},"message":"Kibana dashboards successfully loaded.","service.name":"winlogbeat","ecs.version":"1.6.0"}
Loaded dashboards
{"log.level":"info","@timestamp":"2023-05-28T00:22:10.500-0400","log.logger":"esclientleg","log.origin":{"file.name":"eslegclient/connection.go","file.line":108},"message":"elasticsearch url: http://192.168.2.18:9200","service.name":"winlogbeat","ecs.version":"1.6.0"}
{"log.level":"info","@timestamp":"2023-05-28T00:22:10.528-0400","log.logger":"esclientleg","log.origin":{"file.name":"eslegclient/connection.go","file.line":291},"message":"Attempting to connect to Elasticsearch version 7.17.10","service.name":"winlogbeat","ecs.version":"1.6.0"}


>>>> Loaded Ingest pipelines

# This confirnation that "Kibana Dashboard" and the "indexes" went through successfully, is a "Green light"






# At the same time, we wanted to let "auditbeat" run from our Kali Linux Machine, and this went through "successfully" as "Winlogbeat" did. 



     $ auditbeat setup -e 


2023-05-28T02:00:35.279-0400    INFO    [index-management]      idxmgmt/std.go:435      Set settings.index.lifecycle.rollover_alias in template to {auditbeat-7.17.10 {now/d}-000001} as ILM is enabled.
2023-05-28T02:00:35.279-0400    INFO    [index-management]      idxmgmt/std.go:439      Set settings.index.lifecycle.name in template to {auditbeat {"policy":{"phases":{"hot":{"actions":{"rollover":{"max_age":"30d","max_size":"50gb"}}}}}}} as ILM is enabled.
2023-05-28T02:00:35.284-0400    INFO    template/load.go:197    Existing template will be overwritten, as overwrite is enabled.
2023-05-28T02:00:35.459-0400    INFO    template/load.go:131    Try loading template auditbeat-7.17.10 to Elasticsearch
2023-05-28T02:00:35.485-0400    INFO    template/load.go:123    Template with name "auditbeat-7.17.10" loaded.
2023-05-28T02:00:35.486-0400    INFO    [index-management]      idxmgmt/std.go:296      Loaded index template.
2023-05-28T02:00:35.488-0400    INFO    [index-management.ilm]  ilm/std.go:126  Index Alias auditbeat-7.17.10 exists already.
Index setup finished.
Loading dashboards (Kibana must be running and reachable)
2023-05-28T02:00:35.490-0400    INFO    kibana/client.go:180    Kibana url: http://192.168.2.18:5601
2023-05-28T02:00:35.690-0400    INFO    kibana/client.go:180    Kibana url: http://192.168.2.18:5601
2023-05-28T02:00:38.210-0400    INFO    [add_cloud_metadata]    add_cloud_metadata/add_cloud_metadata.go:101    add_cloud_metadata: hosting provider type not detected.



>>>>>>> 2023-05-28T02:00:39.932-0400    INFO    instance/beat.go:881    Kibana dashboards successfully loaded.
 
 
 >>>>>>Loaded dashboards
                                    

- Lastly, make sure to "Ping and Authenticate against the ElasticSeach Server API", just to ensure that this works properly : 


# -u : Stating out the "Username" or "Password"
# -v : verbose "Output"



- Run the curl commnad against the Elasticsearch Server API :
  
  
            $ curl -v -u root http://192.168.2.18:5601 
         
┌──(root㉿kali)-[/kali/kali]                                                                                                                    
└─# curl -v -u root http://192.168.2.18:5601 
Enter host password for user 'root':                                                                                                               
*   Trying 192.168.2.18:5601...                                          
* Connected to 192.168.2.18 (192.168.2.18) port 5601 (#0)
* Server auth using Basic with user 'root'
> GET / HTTP/1.1        
> Host: 192.168.2.18:5601
> Authorization: Basic cm9vdDprYWxp
> User-Agent: curl/7.88.1                                                
> Accept: */*
>                              
< HTTP/1.1 302 Found                                                                                                                               
< location: /spaces/enter                                                
< x-content-type-options: nosniff
< referrer-policy: no-referrer-when-downgrade            
< content-security-policy: script-src 'unsafe-eval' 'self'; worker-src blob: 'self'; style-src 'unsafe-inline' 'self'
< kbn-name: kali
< kbn-license-sig: 49bde2501362b0371394dd0b193ecec8c00251d991c0fdaf330b60f59f0b5c10
< cache-control: private, no-cache, no-store, must-revalidate
< content-length: 0      
< Date: Sun, 28 May 2023 06:09:44 GMT
< Connection: keep-alive
< Keep-Alive: timeout=120
<                        
* Connection #0 to host 192.168.2.18 left intact



# Note : Make sure to enable the "Winlogbeat service" from "Services.msc",



                    ********//// Kibana Log Issues - WinlogBeat/AuditBeat/filebeat not pulling logs ////*********** 


# Surprisingly, in real-time, no logs were acquired through "Winlogbeats", when the url was accessed, http://192.168.2.18:5601. 





# Let's perform some checks and try to "reproduce any steps" which may have been "left out" : 




               ********/// Verify the Nodes - Auditbeat/Filebeat/WinlogBeat /////************


- Let's run the command below :  

C:\Program Files\Winlogbeat>curl -X GET "http://192.168.2.18:9200/_cat/indices?v"

health status index                                  uuid                   pri rep docs.count docs.deleted store.size 

pri.store.size
yellow open   auditbeat-7.17.10-2023.05.22-000001    3xOnvyeUQMmNJwOdTZbrVQ   1   1          0            0       227b           227b
green  open   .geoip_databases                       HJ8nfNE6RQCRk3WtbTjoTg   1   0         43            3     43.8mb         43.8mb
green  open   .apm-custom-link                       KipPBuAjQ-mqDhFsX0qx_w   1   0          0            0       227b           227b
yellow open   .ds-winlogbeat-8.8.0-2023.05.26-000001 KdgkJW3SQ5KBABE4tSpqMQ   1   1          0            0       227b           227b
green  open   .apm-agent-configuration               TAI3jvTATc2hokZ89gutvw   1   0          0            0       227b           227b
green  open   .kibana_7.17.10_001                    AdQVjk1TS9uaBK0KirCpug   1   0       3669          720      3.7mb          3.7mb
green  open   .async-search                          0wQb02e8QxiX1AV-CuL2uA   1   0          0            4      3.5kb          3.5kb
green  open   .kibana_task_manager_7.17.10_001       y_5eoUqzS8WfzXgCwqte8A   1   0         17        37002      4.5mb          4.5mb
yellow open   filebeat-7.17.10-2023.05.28-000001     DayMqCcQTYaTIHOZWVDAEQ   1   1          0            0       227b           227b
green  open   .tasks                                 gH9KsmsjS5CaEo-cv--AAQ   1   0          4            0     27.4kb         27.4kb



# Similarly, we could check an "https" node without any "certificates", using the same command as above, but simply adding "-k" as follows ;  



    $ curl -X GET -k  https://192.168.2.18:9200
  


# From management >>>> Devtool run the  followimg instance : 



GET _cat/indices?v 


#! Elasticsearch built-in security features are not enabled. Without authentication, your cluster could be accessible to anyone. See https://www.elastic.co/guide/en/elasticsearch/reference/7.17/security-minimal-setup.html to enable security.
health status index                                  uuid                   pri rep docs.count docs.deleted store.size pri.store.size



>>>>>> yellow open   auditbeat-7.17.10-2023.05.22-000001    3xOnvyeUQMmNJwOdTZbrVQ   1   1          0            0       227b           227b

green  open   .geoip_databases                       HJ8nfNE6RQCRk3WtbTjoTg   1   0         43            3     43.8mb         43.8mb

green  open   .apm-custom-link                       KipPBuAjQ-mqDhFsX0qx_w   1   0          0            0       227b           227b

 >>>>>>> yellow open   .ds-winlogbeat-8.8.0-2023.05.26-000001 KdgkJW3SQ5KBABE4tSpqMQ   1   1          0            0       227b           227b

green  open   .kibana_7.17.10_001                    AdQVjk1TS9uaBK0KirCpug   1   0       3667          721      3.9mb          3.9mb
green  open   .apm-agent-configuration               TAI3jvTATc2hokZ89gutvw   1   0          0            0       227b           227b
green  open   .async-search                          0wQb02e8QxiX1AV-CuL2uA   1   0          0            4      3.5kb          3.5kb
green  open   .kibana_task_manager_7.17.10_001       y_5eoUqzS8WfzXgCwqte8A   1   0         17        36012      4.4mb          4.4mb



>>>>> yellow open   filebeat-7.17.10-2023.05.28-000001     DayMqCcQTYaTIHOZWVDAEQ   1   1          0            0       227b           227b

green  open   .tasks                                 gH9KsmsjS5CaEo-cv--AAQ   1   0          4            0     27.4kb         27.4kb






                                            **********////// Security section( xpack features )  - ElasticSearch - Creating http.ssl + TLS  Certificate ( Root CA  + .key + .cert ) ************////////



# Check our "Elasticsearch Stack Server", which is our "Kali Linux machine" itself,  so let's head to this "path location",  "/etc/elasticsearch/elasticsearch.yml". 



- At "security Section" of "ElasticSearch.yml" file, let's start analyzing from the "xpack.features" the features : 



# Let's create a "bash script", so we can save a little bit of time upfront,while re-installing the elasticsearch :

  
  $ vi install.sh 


# Add in the following lines into the "bash script" : 



!#/bin/bash

wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get install apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt-get update && sudo apt-get install elasticsearch



# Make the file executable : 


 $  chmod +x install.sh


# Ww're good to run the script : 


  $  ./install.sh  



                  *******//// Letsencrypt SSL Kali Machine  http.p12 + transport.p12 equivalent **********////// 


# Prior to running the "Letsencrypt, certbot", we'll first need to inatall the following using the commands below : 



- Run the apt update command : 


  $ sudo apt update 


# Now proceed with the below command to start the installation : 


    $ sudo apt -y install certbot


# Upgrade the Certbot application :

  
    $ sudo apt upgrade certbot



                                    ****/// Creating a "Root Self-Signed Certificate" for testing purposes ***/////


 # The idea,  here is not to implement this in production, rather this is just an example, where we want to create a "Root Certificate" using "Local Domain" for Local development server, at the "IP Address, 192.168.2.18"


# Note : "Local Doamain Server Name" could be anything,,, for e.g, "yashil.local"


- Ensure that "Local Domain name", yashil.local is mapped to the IP Address of our Local Development Server, "IP = 192.168.2.18"  at the host file path : "/etc/hosts"


# Simply add in the following for the corresponding local Domain name; guerrier.local :



 192.168.2.18 guerrier.local



- Move on with creating the "Self-Signed Certificate" needed for the Local Domain : 
  
  
  $ sudo certbot certonly --standalone --selfsigned --cert-name guerrier.local --email yashilmohadawoo@gmail.com



# Upon confirmation without any errors, make sure to check if the "certificate' has been generated within this directory : 


  $ cd  /etc/letsencrypt/archive 





# Important : Experiencing issues with creating a certificate with "Letsencrypt", instead we'll proceed with "Openssl".


              
              
                        ********/// Using  "Openssl" to generate a Certificate + private key *********////


# The need arise to create a certificate and a private key is due to the fact that we want to implement "TLS/SSL authentication" from clients to the server node, "elasticsearch".





- Use this command to rapidly create a `certificate` and a `private key` : 


┌──(root㉿kali)-[/var/log/letsencrypt]                                                                           

└─# openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout private.key -out certificate.crt -subj "/CN=192.1
68.2.18"                                                                                                         



++++++++++++++++*.......+......+.....+....+...+...+..............+...+.+.....+....+...+..+..........+........+...
.........+...+....+...+......+.....+.+...+......+..++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+++*...........+...+.........+.+..+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++              
..+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*.+...+......+...............+...+...+...+....
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*.+............+........+.+.....................
+.....+.......+...+............+.....+......+.......+..+.+.....+.+......+..++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++                                                                                      
-----                           




# Check the validity of the certificate : 
                                                        
┌──(root㉿kali)-[/var/log/letsencrypt]                  

└─# openssl x509 -in certificate.crt -text -noout                                                                
                                                                                                                 
Certificate:                                                                                                     
    Data:                                                                                                        
        Version: 3 (0x2)                                                                                         
        Serial Number:                                  
            55:6e:da:ea:8b:e3:7d:19:cc:9a:97:fc:ef:a0:4f:79:95:3f:a4:42
        Signature Algorithm: sha256WithRSAEncryption                                                             
        Issuer: CN = 192.168.2.18                       
        Validity                                        
            Not Before: Jun  1 05:15:31 2023 GMT                                                                 
            Not After : May 31 05:15:31 2024 GMT                                                                 
        Subject: CN = 192.168.2.18                      
        Subject Public Key Info:                        
            Public Key Algorithm: rsaEncryption                                                                  
                Public-Key: (2048 bit)                                                                                          




              *******//// Validating Our Private keys + Certificate  through the Public Key (should match) ****///////  


# Create a "Public Key" from the existing "private.key" : 


┌──(root㉿kali)-[/var/log/letsencrypt]                                                        


└─# openssl pkey -pubout -in private.key | openssl sha256                                                        

 >>>>>>>>>> SHA2-256(stdin)= 704b9c8ce5987cc57b48325ce652a2ce20d1241b276e3fa43b537af00b79ed9a                                
                                                                                              



# Creating a "Public Key" from the exisitng, "certificate", certificate.crt : 

┌──(root㉿kali)-[/var/log/letsencrypt]                                                                           

└─# openssl x509 -pubkey -in certificate.crt -noout | openssl  sha256                       


 >>>>>>>>> SHA2-256(stdin)= 704b9c8ce5987cc57b48325ce652a2ce20d1241b276e3fa43b537af00b79ed9a                                
                                                                                            

# Both `pub.key`, matches, so we`re good  to use our "certificate" and "private.key". 



# Remember : These "certificate and private.key", will be used for both "Kibana" and "ElasticSearch". 








                                                                             ******/////// Generating a `.csr(Certificate Signing Request) + Self Signed Certificate`  **********//////////




# Generating a `Certificate Signing Request` : 



      $ openssl req  -new -nodes  -newkey rsa:4096 -keyout key.pem -out cert.csr



- Country Name ( 2 Letter code )  : UK

- State or Province Name : London

- Locality Name : London




# Generate a `self-signed certificate`: 


  $ openssl req -x509 -newkey -nodes rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 




  # Inspect the `cert.pem`, using the below command : 


              $ openssl x509 -in cert.pem -text


Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            2b:29:0c:2f:b0:52:3a:79:89:1f:82:11:07:bd:9d:84:2a:23:d5:1c
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = UK, ST = London, L = London, O = Default Company Ltd
        Validity
            Not Before: Aug 11 11:34:19 2022 GMT
            Not After : Feb 25 11:34:19 2039 GMT
        Subject: C = UK, ST = London, L = London, O = Default Company Ltd
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (4096 bit)
                Modulus:
                    00:b2:92:13:57:5a:6f:34:e2:e1:f2:08:55:ae:a9:
                    cd:da:c8:e9:6b:bf:fd:5c:36:6d:d3:de:81:53:60:
                    e9:8a:ec:f6:84:1a:73:31:1a:73:cf:47:62:4a:61:
                    4e:9b:63:0d:ce:7c:74:3b:9e:d1:dc:ef:90:1e:de:
                    1b:fb:89:5c:03:f2:57:58:4a:d6:d1:d0:a5:eb:4d:
                    1f:c8:d7:c7:11:e0:38:c3:c3:20:5c:ef:23:09:71:
                    f7:54:68:78:d7:35:80:07:18:83:4a:ce:c6:82:5d:
                    1c:96:f6:ab:11:67:86:5e:8c:1f:dc:5e:68:65:24:
                    42:6a:51:21:69:87:b2:63:d8:dc:5d:c5:df:bf:cf:








                                                                                       ******//// Elasticsearch.yml + Kibana.yml =  Using Generated TLS/SSL Certificate + Private Key *******///////


 # Once verified, make sure to place these 2 files, specifically, "certificate.crt" + "private.key" under a newly created directory within "elasticsearch"  and  , proceed as follows : 

            
┌──(root㉿kali)-[/etc/elasticsearch]  

 └─# mkdir certs                                                                                                                                       
                                                                                                                                                       
┌──(root㉿kali)-[/etc/elasticsearch]                                                                                                                   

└─# ls                                                                     
certs                   elasticsearch.yaml  jvm.options.d                  

elasticsearch.keystore  elasticsearch.yml                                  


┌──(root㉿kali)-[/etc/elasticsearch]                                       

└─# cd certs                
                                                                           


┌──(root㉿kali)-[/etc/elasticsearch/certs]

└─# ls 

certificate.crt  private.key 


- Refer these 2 files in your "elasticsearch.yml" and prior to any modification, always stop the "elasticsearch service" : 


  $ service elasticsearch stop




# ---------------------------------- Security ----------------------------------
#
#                                 *** WARNING ***
#
# Elasticsearch security features are not enabled by default.
# These features are free, but require configuration changes to enable them.
# This means that users don’t have to provide credentials and can get full access
# to the cluster. Network connections are also not encrypted.
#
# To protect your data, we strongly encourage you to enable the Elasticsearch security features. 
# Refer to the following documentation for instructions.
#
# https://www.elastic.co/guide/en/elasticsearch/reference/7.16/configuring-stack-security.html


# Enable security features

>>>>>> xpack.security.enabled: true

>>>> xpack.security.enrollment.enabled: true

# Enable encryption for HTTP API client connections, such as Kibana, Logstash, and Agents


# Note :  Below we've been able to reference, the path location of the "certificate and private key" , /etc/elasticsearch/certs in both "http.ssl " and "transport.ssl". 



>>>>> xpack.security.http.ssl:
  >>>>> enabled: true


>>>>>  key: /etc/elasticsearch/certs/private.key

>>>>   certificate: /etc/elasticsearch/certs/certificate.crt

# Enable encryption and mutual authentication between cluster nodes

>>>>> xpack.security.transport.ssl:
 >>>>  enabled: true


>>>>>  key: /etc/elasticsearch/certs/private.key

>>>>>>  certificate: /etc/elasticsearch/certs/certificate.crt



# Make sure that the "Ownership", of our files and the "certs folder" belongs to "Elasticsearch", currently, our files still have "root" ownership. Let's affect this.



┌──(root㉿kali)-[/etc/elasticsearch/certs]
└─# ls -larh 
total 16K
-rw-r----- 1 elasticsearch root          1.7K Jun  1 01:15 private.key
-rw-r--r-- 1 elasticsearch root          1.1K Jun  1 01:15 certificate.crt
drwxr-s--- 4 root          elasticsearch 4.0K Jun  1 08:53 ..
drwxr-sr-x 2 elasticsearch root          4.0K Jun  1 01:30 .



# Use "chown -R" , to change the ownership of our target files :  



(root㉿kali)-[/etc/elasticsearch/certs]

└─# chown  -R elasticsearch:elasticsearch ./          
                                                                                                                                            
                                                                                                           
┌──(root㉿kali)-[/etc/elasticsearch/certs]

└─# ls -larh 

total 16K
-rw-r----- 1 elasticsearch elasticsearch          1.7K Jun  1 01:15 private.key
-rw-r--r-- 1 elasticsearch elasticsearch      1.1K Jun  1 01:15 certificate.crt
drwxr-s--- 4 root          elasticsearch 4.0K Jun  1 08:53 ..
drwxr-sr-x 2 elasticsearch elasticsearch          4.0K Jun  1 01:30 .






# Use the "chmod command", to affect "read permissions" to our "certificate.crt" file and "private.key" file :  


$ chmod g+r /etc/elasticsearch/certs/certificate.crt


$ chmod g+r /etc/elasticsearch/certs/private.key






                      ******//// Ownership Change + Read Permission **********////// 


# Similarly, add in the same "private key and Certificate" , under the "kibana.yml", within "System: Kibana Server" 


                        /etc/kibana/kibana.yml                                                              
# -----------------------------System: Kibana Server  (Optional)  ---------------------------------# 

# Enables SSL and paths to the PEM-format SSL certificate and SSL key files, respectively.
# These settings enable SSL for outgoing requests from the Kibana server to the browser.



>>>> server.ssl.enabled: true

>>>>> server.ssl.certificate: /etc/kibana/certs/certificate.crt

>>>> server.ssl.key: /etc/kibana/certs/private.key

# Optional settings that provide the paths to the PEM-format SSL certificate and key files.
# These files are used to verify the identity of Kibana to Elasticsearch and are required when
# xpack.security.http.ssl.client_authentication in Elasticsearch is set to required.
#elasticsearch.ssl.certificate: /path/to/your/client.crt
#elasticsearch.ssl.key: /path/to/your/client.key

# Optional setting that enables you to specify a path to the PEM file for the certificate
# authority for your Elasticsearch instance.
#elasticsearch.ssl.certificateAuthorities: [ "/path/to/your/CA.pem" ]

# To disregard the validity of SSL certificates, change this setting's value to 'none'.
elasticsearch.ssl.verificationMode: full




# Next up, let's start adding the same "ownership and permission" to our kibana certs "dieectory".   



- Changing ownership "Owner:Group" : 

root@kali[/etc/kibana]                                                                                                                          

  $ sudo chown -R kibana:kibana ./ 


┌──(root㉿kali)-[/etc/kibana]    

└─# ls -larh                                                                                                     

0total 64K                                               

-rw-r--r--   1 kibana kibana  305 Apr 27 07:18 node.options
-rw-r--r--   1 kibana kibana 5.4K May 29 02:13 kibana.yml.save                                                   
-rw-r--r--   1 kibana kibana 7.6K May 23 20:45 kibana.yml.old                                                    
-rw-r--r--   1 kibana kibana 5.2K May 25 13:10 kibana.yml.dpkg-dist                                              
-rw-r--r--   1 kibana kibana 6.0K Jun  1 10:37 kibana.yml                                                        
-rw-r--r--   1 kibana kibana   62 May 22 11:52 .kibana.keystore.initial_md5sum                                    
-rw-rw----   1 kibana kibana  266 May 28 02:28 kibana.keystore             
drwxr-sr-x   2 kibana kibana 4.0K Jun  1 10:30 certs                       
drwxr-xr-x 196 root   root    12K Jun  1 01:52 ..                          
drwxr-s---   3 kibana kibana 4.0K Jun  1 11:06 .                           


# Start Kibana : 

  $ sudo service kibana start



# Finally, we're good to start "elasticsearch" ;


  $ systemctl enable elasticsearch


 - Initiate "ElasticSearch" :

  
  $  service elasticsearch start


# Unfortunately, we're encountering some issues during the "booting process", see below : 


- Let's verify the logs, "elasticsearch" : 

$ journalctl  --unit elasticsearch

$ journalctl  -xeu elasticsearch



May 22 03:54:15 kali systemd-entrypoint[817303]:         at io.netty.util.concurrent.SingleThreadEventExecutor$4.run(SingleThreadEventExecu>
May 22 03:54:15 kali systemd-entrypoint[817303]:         at io.netty.util.internal.ThreadExecutorMap$2.run(ThreadExecutorMap.java:74)
May 22 03:54:15 kali systemd-entrypoint[817303]:         at java.base/java.lang.Thread.run(Thread.java:1623)
May 22 03:54:15 kali systemd-entrypoint[817303]: For complete error details, refer to the log at /var/log/elasticsearch/elasticsearch.log
May 22 03:54:16 kali systemd[1]: elasticsearch.service: Main process exited, code=exited, status=1/FAILURE


>>>>>
>>>>>> May 22 03:54:16 kali systemd[1]: elasticsearch.service: Failed with result 'exit-code'.
>>>>>>


May 22 03:54:16 kali systemd[1]: Failed to start elasticsearch.service - Elasticsearch.
May 22 03:54:16 kali systemd[1]: elasticsearch.service: Consumed 47.059s CPU time.
May 22 03:55:07 kali systemd[1]: Starting elasticsearch.service - Elasticsearch...
May 22 03:55:29 kali systemd-entrypoint[818274]: uncaught exception in thread [main]
May 22 03:55:29 kali systemd-entrypoint[818274]: BindTransportException[Failed to bind to 192.168.2.15:[9300-9400]]; nested: BindException[>
May 22 03:55:29 kali systemd-entrypoint[818274]: Likely root cause: java.net.BindException: Cannot assign requested address
May 22 03:55:29 kali systemd-entrypoint[818274]:         at java.base/sun.nio.ch.Net.bind0(Native Method)
May 22 03:55:29 kali systemd-entrypoint[818274]:         at java.base/sun.nio.ch.Net.bind(Net.java:556)




# Important : Since the issue with "ElasticSearch" on boot up is persistent, instead we'll  reproduce these steps above, by installing "ElasticSearch" inside of a "Docker Container" and then we'll observe the behaviour. 







                                  ***********//// Installation of an ElasticSearch Server + Kibana - Docker Container  /////**********************


# Let's "git clone" this repository : 


  $ git clone https://github.com/justmeandopensource/elk
                                                                                                                                                                  
Resolving deltas: 100% (33/33), done.                                                                                                                                                                                                                                                                                                

# We'll now "cd" into the repository  : 

  $ cd /elk/docker 



# Transfer the "configuration" to our "docker-compose.yml", since we'll be adapting this lab with the "elasticsearch version", "docker-compose-v7.9.2.yml", and given that we'll be working with the "docker-compose.yml"  file  at all times : 



  $  docker-compose-v7.9.2.yml docker-compose.yml    



# Let's run and "start" the docker container : 


  $ sudo systemctl start docker



# Beforehand, let's make sure that elasticsearch has the "Kernel Parameter"" properly setup and persistent throughout "reboot" : 


  $ sudo sysctl -w vm.max_map_count=262144 


# Let's add this onto the location path, /etc/sysctl.conf and make it "persistent" : 

  $ sudo vi /etc/sysctl.conf 

#  Add the line  : sysctl -w vm.max_map_count=262144 



# On your first time, "docker-compose up -d" will basically install and create the "elasticsearch and kibana" instance, and on the next time this will simply run the components (Elasticsearch + Kibana) : 

  $ docker-compose up -d 

──(root㉿kali)-[/opt/elk/docker]                                                                                                               
[0/325]
└─#  docker-compose up -d 

Creating network "docker_default" with the default driver                  
Creating volume "docker_esdata1" with local driver                         
Pulling elasticsearch (docker.elastic.co/elasticsearch/elasticsearch:7.9.2)...                                                                         
7.9.2: Pulling from elasticsearch/elasticsearch                            
f1feca467797: Pull complete          
2b669da077a4: Pull complete      
e5b4c466fc6d: Pull complete
3b660c013f1a: Pull complete      
0e7ad1133ad1: Pull complete
b50d6e48f432: Pull complete      
bff3705905f9: Pull complete
9509765886ad: Pull complete                                                
b7f06f509306: Pull complete          
Digest: sha256:2be3302537236874fdeca184c78a49aed17d5aca0f8fc3f6192a80e93e817cb4                                                                        
Status: Downloaded newer image for docker.elastic.co/elasticsearch/elasticsearch:7.9.2                                                                 
Pulling kibana (docker.elastic.co/kibana/kibana:7.9.2)...                  
7.9.2: Pulling from kibana/kibana    
f1feca467797: Already exists     
931233f554d6: Pull complete
581a489dbecb: Pull complete      
aa6fbd91b2db: Pull complete
bff28ae590a6: Downloading [==============================>                    ]  210.9MB/346.3MB                                                       
ad686c2de296: Download complete
65ff4ca7a663: Download complete      
f0eefcb039b2: Download complete  
a742df43ef13: Download complete
6f64f5502816: Download complete  
3bffd6feec15: Download complete
                                  
3bffd6feec15: Pull complete
Digest: sha256:48d7d2e91b7903321748432e22a01576c7e4db539021836b54bd58d5659aa5e5
Status: Downloaded newer image for docker.elastic.co/kibana/kibana:7.9.2

>>>>>>> Creating elasticsearch ... 

# Let's verify, if the "Kibana and elasticsearch" is running fine :  


  $ docker-compose ps



┌──(root㉿kali)-[/opt/elk/docker]

└─# docker-compose ps
    Name                Command            State            Ports          
---------------------------------------------------------------------------
elasticsearch   /tini --                   Up      0.0.0.0:9200-           
                /usr/local/bin/do ...              >9200/tcp,:::9200-      
                                                   >9200/tcp, 9300/tcp     
kibana          /usr/local/bin/dumb-init   Up      0.0.0.0:5601-           
                - ...                              >5601/tcp,:::5601-      
                                                   >5601/tcp               






# Let's observe the logs and keep this separate on a different "Terminal pane": 


  $ docker-compose logs  -f 

>>>>>> Elasticsearch starting up : 

>>>>>> elasticsearch    | {"type": "server", "timestamp": "2023-06-01T17:33:37,216Z", "level": "INFO", "component": "o.e.x.i.a.

TransportPutLifecycleAction", "cluster.name": "docker-cluster", "node.name": "elasticsearch", "message": "adding index lifecycle policy [slm-history-ilm-policy]", "cluster.uuid": "8r2Tq1kZTki7bhoGH4K_BQ", "node.id": "B7G_MQc7Rgy3pixqf66C9w"  }                                                                                          


>>>>>>> elasticsearch    | {"type": "server", "timestamp": "2023-06-01T17:33:38,192Z", "level": "INFO", "component": "o.e.l.LicenseService", 


"cluster.name": "docker-cluster", "node.name": "elasticsearch", "message": "license [5e5f4b8a-d6fd-4d28-aa8e-601501863196] mode [basic] - valid", "cluster.uuid": "8r2Tq1kZTki7bhoGH4K_BQ", "node.id": "B7G_MQc7Rgy3pixqf66C9w"  }                                                                                              elasticsearch    | {"type": "server", "timestamp": "2023-06-01T17:33:38,208Z", "level": "INFO", "component": "o.e.x.s.s.SecurityStatusChangeListener", 
"cluster.name": "docker-cluster", "node.name": "elasticsearch", "message": "Active license is now [BASIC]; Security is disabled", "cluster.uuid": "8r2Tq1kZTki7bhoGH4K_BQ", "node.id": "B7G_MQc7Rgy3pixqf66C9w"  }                                                                                            kibana           | {"type":"log","@timestamp":"2023-06-01T17:32:24Z","tags":["warning","plugins-discovery"],"pid":6,"message":"Expect plugin \"id\" in 
camelCase, but found: beats_management"}                                                                                                               
kibana           | {"type":"log","@timestamp":"2023-06-01T17:32:24Z","tags":["warning","plugins-discovery"],"pid":6,"message":"Expect plugin \"id\" in camelCase, but found: triggers_actions_ui"}                                                                                                            




# Important : Unfortunately, "Kibana" did not go to completion, so we 'll have to "adjust" the "docker-compose.yml file", and try again ; 


>>>>> Kibana starting up : 


>>>>>> kibana           | [BABEL] Note: The code generator has deoptimised the styling of /usr/share/kibana/x-pack/plugins/canvas/server/templates/

pitch_presentation.js as it exceeds the max of 500KB.                                                                                                             
kibana           | {"type":"log","@timestamp":"2023-06-01T17:34:35Z","tags":["info","plugins-service"],"pid":6,"message":"Plugin \"visTypeXy\" is disabled."}                                                                                                                                                


 >>>>>> kibana           | {"type":"log","@timestamp":"2023-06-01T17:34:35Z","tags":







  # Let's now jump to our previously installed "auditbeat",  and test the "auditbeat configuration" : 


    $ sudo auditbeat test config


┌──(root㉿kali)-[/usr/share/kibana/config]

└─# auditbeat test output  

elasticsearch: http://192.168.2.18:9200...
  parse url... OK
  connection...
    parse host... OK
    dns lookup... OK
    addresses: 192.168.2.18
    dial up... OK
  TLS... WARN secure connection disabled
b  talk to server... OK
  version: 7.17.0



# Let's test with the "output" command, in order to check that the communication between "auditbeat" and "ElasticSearch Server"  : 


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


# Setting up the "Kibana Dashboard", "Indexes" : 


    $ sudo auditbeat setup -e 




# Below is a particular situation, where our The auditbeat service cannot grab and communicate with kibana, as the `Kibana version (currently is at 9.5.2)` needs to be at least "7.14.0". 




┌──(root㉿kali)-[/etc/elasticsearch]


# auditbeat setup       

Overwriting ILM policy is disabled. Set `setup.ilm.overwrite: true` for enabling.

Index setup finished.
Loading dashboards (Kibana must be running and reachable)
Exiting: Error importing Kibana dashboards: fail to import the dashboards in Kibana: Error importing directory /usr/share/auditbeat/kibana: failed 

>>>>> # to import Kibana index pattern: Kibana version must be at least 7.14.0



# Unfortunately, the version of Elasticsearch + Kibana, should match that of the auditbeat Version as described below ;  


  $  dpkg -s auditbeat            


Package: auditbeat               
Status: install ok installed                                                                                                                
Priority: extra                
Section: default                                                      
Installed-Size: 102474             
Maintainer: <@a146c710fd2d>      
Architecture: amd64            
Version: 7.17.10                                                                                                                            
Conffiles:                         
 /etc/auditbeat/audit.rules.d/sample





              **********//// Remediating the "docker-compose.yml" file - ElasticSearch + Kibana ( Version 7.17 ) /////*********


# Let's head to this 'path location' : 


  $ cd /opt/elk/docker



# Prior to any modification on the "docker-compose.yml file", stop the "Docker Container and its Instances(elasticsearch + Kibana - Version 9.5.2)" :  


  $ sudo docker-compose down 



# Modify the "docker-compose.yml", such that the "new version" is set at 7.17, as well as, the the instances binds itself onto the http://192.168.2.18, rather than the "Localhost" ; 


{

version: '2.2'

services:

  elasticsearch:
# Image modified to "Version", 7.17 ; 

    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.0

    container_name: elasticsearch

    environment:

      - node.name=elasticsearch

      - discovery.seed_hosts=elasticsearch

      - cluster.initial_master_nodes=elasticsearch

      - cluster.name=docker-cluster

      - bootstrap.memory_lock=true

      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"

      - network.host=0.0.0.0

    ulimits:

      memlock:

        soft: -1

        hard: -1

    volumes:

      - esdata1:/usr/share/elasticsearch/data


# IP Address, affected to 192.168.2.18, for ElasticSearch at :9200 port. 

    ports:
      - 192.168.2.18:9200:9200

  kibana:

    image: docker.elastic.co/kibana/kibana:7.17.0

    container_name: kibana

    environment:


# We would refer the ELASTICSEARCH_URL: "http://elasticsearch:9200", since this is a "Docker Container", and in this case our Kibana instance identify ElasticSearch Server, from their "container_name: elasticsearch" ; 

      ELASTICSEARCH_URL: "http://elasticsearch:9200"


# Instead of confusing "Kibana Instance", here we're requesting that it "listens" on all "Network Interfaces available"  so it picks up easily on our "ElasticSearch Stack Server" ; 
 
      SERVER_HOST: "0.0.0.0"

# Below we're specifying the IP Address, affected to 192.168.2.18 (ElasticServer), for kibana, at port :5601.

    ports:

      - 192.168.2.18:5601:5601

    depends_on:

      - elasticsearch

volumes:

  esdata1:

    driver: local



# Here we're again, starting "docker-compose", with the "Newly applied Version 7.17" ; 


┌──(root㉿kali)-[/opt/elk/docker]                                                                                                   
[0/1882]

└─# docker-compose up -d 


Creating network "docker_default" with the default driver             
Pulling elasticsearch (docker.elastic.co/elasticsearch/elasticsearch:7.17.0)...                                                             
7.17.0: Pulling from elasticsearch/elasticsearch                      
c661c71060f1: Pull complete
cdbad67ce350: Pull complete      
9b97d3778e89: Pull complete    
a84640b8c73b: Downloading [========================================>          ]  275.2MB/337.7MB                                            
75dda725ba6b: Download complete  




# Let's enable and start the "auditbeat" service : 

  $ systemctl enable  --now  auditbeat



# Start Auditbeat : 

  $ service auditbeat start 


# Verify Auditbeat's status : 


  $ service auditbeat status
  

                                     ******//// Final Steps Checking API Responsiveness - Analyzing logs /////*********



# Let's now run the "Auditbeat" setup : 



# Indices loaded to completion : 

2023-06-02T23:22:54.405-0400    INFO    [index-management]      idxmgmt/std.go:439      Set settings.index.lifecycle.name in template to {auditbeat {"policy":{"phases":{"hot":{"actions":{"rollover
":{"max_age":"30d","max_size":"50gb"}}}}}}} as ILM is enabled.                                    
2023-06-02T23:22:54.415-0400    INFO    template/load.go:197    Existing template will be overwritten, as overwrite is enabled.
2023-06-02T23:22:54.804-0400    INFO    template/load.go:131    Try loading template auditbeat-7.17.10 to Elasticsearch
2023-06-02T23:22:54.866-0400    INFO    template/load.go:123    Template with name "auditbeat-7.17.10" loaded.



>>>>> 2023-06-02T23:22:54.866-0400    INFO    [index-management]      idxmgmt/std.go:296      Loaded index template.


2023-06-02T23:22:54.871-0400    INFO    [index-management.ilm]  ilm/std.go:126  Index Alias auditbeat-7.17.10 exists already.
Index setup finished.                                                                             
Loading dashboards (Kibana must be running and reachable)                                         
2023-06-02T23:22:54.871-0400    INFO    kibana/client.go:180    Kibana url: http://192.168.2.18:5601
2023-06-02T23:22:55.166-0400    INFO    kibana/client.go:180    Kibana url: http://192.168.2.18:5601
2023-06-02T23:22:57.244-0400    INFO    [add_cloud_metadata]    add_cloud_metadata/add_cloud_metadata.go:101     add_cloud_metadata: hosting provider type not detected.


# Kibana Dashboards loaded perfectly : 

 >>>>> 2023-06-02T23:23:06.683-0400    INFO    instance/beat.go:881    Kibana dashboards successfully loaded.
 >>>>>> Loaded dashboards                                                                                 








# Important Suggestion : Keep the command, "docker-compose logs -f", running on a separate terminal pane at all times, as this will allow us to check the "responsiveness" of any "triggered action" made against the API ElasticSearch API. 



- Great !!, we'll verify the "docker-compose" logs, this time around both "Kibana and ElasticSaerch" executed without any errors as seen below : 



# Run the below command : 


    $ docker-compose logs -f 

 # ElasticSearch Logs : 

elasticsearch    | {"type": "server", "timestamp": "2023-06-03T01:11:13,056Z", "level": "INFO", "component": "o.e.c.m.MetadataMappingService", "cluster.name": "docker-cluster", "node.name": "elasticsearch", "message": "[auditbeat-7.17.10-2023.06.01-000001/JjKdxEDeThOV3AZ2Z51jVA] update_mapping [_doc]", "cluster
.uuid": "8r2Tq1kZTki7bhoGH4K_BQ", "node.id": "B7G_MQc7Rgy3pixqf66C9w"  }                                                                                                                                                                                                                                                
elasticsearch    | {"type": "server", "timestamp": "2023-06-03T01:11:15,225Z", "level": "INFO", "component": "o.e.c.m.MetadataMappingService", "cluster.name": "docker-cluster", "node.name": "elasticsearch", "message": "[auditbeat-7.17.10-2023.06.01-000001/JjKdxEDeThOV3AZ2Z51jVA] update_mapping [_doc]", "cluster
.uuid": "8r2Tq1kZTki7bhoGH4K_BQ", "node.id": "B7G_MQc7Rgy3pixqf66C9w"  }      
elasticsearch    | {"type": "server", "timestamp": "2023-06-03T01:11:18,550Z", "level": "INFO", "component": "o.e.c.m.MetadataMappingService", "cluster.name": "docker-cluster", "node.name": "elasticsearch", "message": "[auditbeat-7.17.10-2023.06.01-000001/JjKdxEDeThOV3AZ2Z51jVA] update_mapping [_doc]", "cluster
.uuid": "8r2Tq1kZTki7bhoGH4K_BQ", "node.id": "B7G_MQc7Rgy3pixqf66C9w"  }      
elasticsearch    | {"type": "server", "timestamp": "2023-06-03T01:11:20,566Z", "level": "INFO", "component": "o.e.c.m.MetadataMappingService", "cluster.name": "docker-cluster", "node.name": "elasticsearch", "message": "[auditbeat-7.17.10-2023.06.01-000001/JjKdxEDeThOV3AZ2Z51jVA] update_mapping [_doc]", "cluster
.uuid": "8r2Tq1kZTki7bhoGH4K_BQ", "node.id": "B7G_MQc7Rgy3pixqf66C9w"  }      
elasticsearch    | {"type": "server", "timestamp": "2023-06-03T01:11:22,652Z", "level": "INFO", "component": "o.e.c.m.Me


# Kibana Logs run successfully : 


kibana           | {"type":"response","@timestamp":"2023-06-03T01:13:24+00:00","tags":[],"pid":7,"method":"get","statusCode":304,"req":{"url":"/plugins/kibanaReact/assets/solutions_enterprise_search.svg","method":"get","headers":{"host":"192.168.2.18:5601","connection":"keep-alive","user-agent":"Mozilla/5.0 (Wi
ndows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36","accept":"image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8","referer":"http://192.168.2.18:5601/app/home","accept-encoding":"gzip, deflate","accept-language":"en-US,en;q=0.9,fr;q=0.8","if-none-match
":"\"8a0bfc03aefd738f58c9302228855eb15120082a\"","if-modified-since":"Fri, 28 Jan 2022 09:07:44 GMT"},"remoteAddress":"192.168.2.22","userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36","referer":"http://192.168.2.18:5601/app/home"},"res":
{"statusCode":304,"responseTime":16,"contentLength":229},"message":"GET /plugins/kibanaReact/assets/solutions_enterprise_search.svg 304 16ms - 229.0B"}                                                                                                                                                                 





  # Sanity Checks : Let's perform some "curl function" against both the "ElasticSearch : 9200 and Kibana : 5601" ; 


                                                                                                                                                                                        


# Checking the ElasticSearchServer : 

   $ curl -v http://192.168.2.18:9200

* Connected to 192.168.2.18 (192.168.2.18) port 9200 (#0)                                                                                          
> GET / HTTP/1.1                                                         
> Host: 192.168.2.18:9200                                                
> User-Agent: curl/7.88.1                                                
> Accept: */*                                                            
>                                                                        
< HTTP/1.1 200 OK                                                        
< X-elastic-product: Elasticsearch                                                                                                                                                                                                                                                                    
< Warning: 299 Elasticsearch-7.17.0-bee86328705acaa9a6daede7140defd4d9ec56bd "Elasticsearch built-in security features are not enabled. Without authentication, your cluster could be accessible to anyone. See https://www.elastic.co/guide/en/elasticsearch/reference/7.17/security-minimal-setup.html to enable security."
< content-type: application/json; charset=UTF-8                          
< content-length: 547                                                    
<                                                                        
{                                                                        
  "name" : "elasticsearch",                                              
  "cluster_name" : "docker-cluster",                                     
  "cluster_uuid" : "8r2Tq1kZTki7bhoGH4K_BQ",                             
  "version" : {                                                          
    "number" : "7.17.0",                                                 
    "build_flavor" : "default",                                          
    "build_type" : "docker",                                             
    "build_hash" : "bee86328705acaa9a6daede7140defd4d9ec56bd",                                                                                     
    "build_date" : "2022-01-28T08:36:04.875279988Z",                                                                                               
    "build_snapshot" : false,                                            
    "lucene_version" : "8.11.1",                                         
    "minimum_wire_compatibility_version" : "6.8.0",                                                                                                
    "minimum_index_compatibility_version" : "6.0.0-beta1"                                                                                          
  },                                                                                                                                               


# Checking Kibana : 

┌──(root㉿kali)-[/home/kali]

└─# curl -v http://192.168.2.18:5601  

*   Trying 192.168.2.18:5601...
* Connected to 192.168.2.18 (192.168.2.18) port 5601 (#0)
> GET / HTTP/1.1
> Host: 192.168.2.18:5601
> User-Agent: curl/7.88.1
> Accept: */*
> 
< HTTP/1.1 302 Found
< location: /spaces/enter
< x-content-type-options: nosniff
< referrer-policy: no-referrer-when-downgrade
< kbn-name: 9bc3f3d1e4ec
< kbn-license-sig: 3427a92e25ee89c1e8530ab7a369a231ff4e2919765d4ced7a80067b42dc788a
< cache-control: private, no-cache, no-store, must-revalidate
< content-length: 0
< Date: Sat, 03 Jun 2023 04:00:53 GMT
< Connection: keep-alive
< Keep-Alive: timeout=120
< 
* Connection #0 to host 192.168.2.18 left intact





                               *****///Implementing Logstash from Filebeat + Nginx Logs ****/////


# Nginx is a module present within "Filebeat" which when "enabled", will allow the Filebeat logs to be captured through the "Nginx tunnel" and be sent to the "Logstash Server" on "port :5044". 



# After fully setting up "Filebeat" and making sure that this works, let us now begin the installation of the "nginx" : 



- Installation of Nginx : 


  $ apt install nginx                                                           


Reading package lists... Done                                                   
Building dependency tree... Done                                                
Reading state information... Done                                               
nginx is already the newest version (1.22.1-9).                      
nginx set to manually installed.                                                
......


# Since this "nginx" co-exist inside of "Filebeat Modules List", let's take a look at the "filebeat modules" list ; 


    $  sudo filebeat modules list
......
...
redis
santa
snort
snyk
sonicwall
sophos
squid
system
threatintel
tomcat
traefik
zookeeper
zoom
.......
... 

# As you can you see that the nginx exist within the "filebeat modules" :  


┌──(root㉿kali)-[/etc/filebeat/modules.d]

└─# sudo filebeat modules list | grep nginx  

 >>> nginx


  

# Let's verify the "nginx file" for its corresponding  "nginx modules.d", under the path location , "/etc/filebeat/modules.d/" : 




  $ ls /etc/filebeat/modules.d /





# Note : All the suffix shows disabled, for e.g, gcp.yml.disabled, unless this is "enable" ; 

┌──(root㉿kali)-[/etc/filebeat/modules.d]
└─# ls 

activemq.yml.disabled     cylance.yml.disabled           iptables.yml.disabled         o365.yml.disabled        sophos.yml.disabled
apache.yml.disabled       elasticsearch.yml.disabled     juniper.yml.disabled          okta.yml.disabled        squid.yml.disabled
auditd.yml.disabled       envoyproxy.yml.disabled        kafka.yml.disabled            oracle.yml.disabled      suricata.yml
awsfargate.yml.disabled   f5.yml.disabled                kibana.yml.disabled           osquery.yml.disabled     system.yml.disabled
aws.yml.disabled          fortinet.yml.disabled          logstash.yml.disabled         panw.yml.disabled        threatintel.yml.disabled
azure.yml.disabled        gcp.yml.disabled               microsoft.yml.disabled        pensando.yml.disabled    tomcat.yml.disabled
barracuda.yml.disabled    googlecloud.yml.disabled       misp.yml.disabled             postgresql.yml.disabled  traefik.yml.disabled
bluecoat.yml.disabled     google_workspace.yml.disabled  mongodb.yml.disabled          proofpoint.yml.disabled  zeek.yml
cef.yml.disabled          gsuite.yml.disabled            mssql.yml.disabled            rabbitmq.yml.disabled    zookeeper.yml.disabled
checkpoint.yml.disabled   haproxy.yml.disabled           mysqlenterprise.yml.disabled  radware.yml.disabled     zoom.yml.disabled
cisco.yml.disabled        ibmmq.yml.disabled             mysql.yml.disabled            redis.yml.disabled       zscaler.yml.disabled
coredns.yml.disabled      icinga.yml.disabled            nats.yml.disabled             santa.yml.disabled
crowdstrike.yml.disabled  iis.yml.disabled               netflow.yml.disabled          snort.yml.disabled
cyberarkpas.yml.disabled  imperva.yml.disabled           netscout.yml.disabled         snyk.yml.disabled
cyberark.yml.disabled     infoblox.yml.disabled          nginx.yml.disabled            sonicwall.yml.disabled
                                                                                                                         


# "Nginx file module" is "disabled" : 


┌──(root㉿kali)-[/etc/filebeat/modules.d]

└─# ls -larh /etc/filebeat/modules.d  | grep nginx 

-rw-r--r-- 1 root root  784 Apr 23 05:00 nginx.yml.disabled



# Enable `nginx.yml` modules; 

┌──(root㉿kali)-[/etc/filebeat/modules.d]

└─# sudo filebeat modules enable nginx     

 >>>> Enabled nginx




# Restart the filebeat.service : 

┌──(root㉿kali)-[/etc/filebeat/modules.d]

└─# systemctl restart  filebeat                                        




# Let's run the "filebeat" setup : 


  $ filebeat setup -e 


 >>>>> Loaded dashboards

2023-06-04T14:56:20.760-0400    WARN    [cfgwarn]       instance/beat.go:606    DEPRECATED: Setting up ML using Filebeat is going to be remoSetting up ML using setup --machine-learning is going to be removed in 8.0.0. Please use the ML app instead.
See more: https://www.elastic.co/guide/en/machine-learning/current/index.html
2023-06-04T14:56:20.760-0400    INFO    [esclientleg]   eslegclient/connection.go:105   elasticsearch url: http://192.168.2.18:9200
2023-06-04T14:56:20.783-0400    INFO    [esclientleg]   eslegclient/connection.go:285   Attempting to connect to Elasticsearch version 7.17.2023-06-04T14:56:20.784-0400    INFO    kibana/client.go:180    Kibana url: http://192.168.2.18:5601
2023-06-04T14:56:20.901-0400    WARN    fileset/modules.go:463  X-Pack Machine Learning is not enabled                              [65/519]
2023-06-04T14:56:20.946-0400    WARN    fileset/modules.go:463  X-Pack Machine Learning is not enabled


 >>>>> #  2023-06-04T14:56:20.947-0400    ERROR   instance/beat.go:1027   Exiting: 1 error: error loading config >>>> file: invalid config: yaml: line 85: did not find expected key                                             

# Error Message : Exiting: 1 error: error loading config file: invalid config: yaml: line 85: did not find expected key
                                                                      


# Let's "manually setup" the "Dashboard" : 

 
  $  filebeat setup --dashboards                 


>>>>>> Loading dashboards (Kibana must be running and reachable) 

 >>>> Loaded dashboards                    



# Very important : In case, we may not have an "index pattern" corresponding to "Filebeat", make sure to create this before analyzing the logs. 




      ************///// Logstash Server Installation + Add "Grok pattern" + Logstash Configuration /////**********
                              




# Proceed with the below command : 


  $  sudo apt-install logstash



┌──(root㉿kali)-[/etc/filebeat/modules.d]

# apt install logstash 

Reading package lists...                                                                                                                         
The following packages were automatically installed and are no longer required:



.........


# Start the Logstash Service : 


  $ sudo systemctl start logstash


  $ sudo systemctl enable logstash


# Check if the "Logstash Service" is up and running : 



  $ sudo systemctl status logstash 



# Important : Always "enable" Logstash Server prior to all the other services like "Kibana", "Elasticsearch". 








- Modifying the "User Account Settings" : 

# Now that, we've installed "nginx and logstash", let's add "Logstash" to the Group "adm";



┌──(root㉿kali)-[/etc/filebeat/modules.d]                                                  

└─# sudo usermod -aG adm logstash                                               
                                        






           *******///// Add in the "grok pattern", /etc/logstash/pattern /////*******


- Add in a grok pattern (help to parse logs) : 


# Let's create a directory within "/etc/logstash",called pattern ;


  $ mkdir /etc/logstash/pattern 



# Let's add in the permissions needed to the : 


┌──(root㉿kali)-[/etc/logstash]

└─# chmod 755 -R /etc/logstash/pattern  



# We'll now create an "nginx file", and add in the following 2 lines ; 




 ┌──(root㉿kali)-[/etc/logstash]
     
         
  # sudo nano /etc/logstash/pattern/nginx                   


- In the text editor, add in these 2 lines, without the ""curly braces" : 

{
NGUSERNAME [a-zA-Z\.\@\-\+_%]+ 
NGUSER %{NGUSERNAME}  
}


# Make sure to enable and start the "Nginx" service ; 


  $ sudo service nginx start



            ***********////// Creating nginx.conf file *******///////////


# We'll need to create an "nginx.conf" file, and make sure to add the "line of code" within the "path directory": /etc/logstash/conf.d/nginx.conf

- From the repository below, you would need to refer to the "nginx.conf" file : 

URL : https://gitlab.com/xavki/devopsland/-/blob/master/elk/03-simple-example/nginx.conf#L11


>>>>>>>>>


# Specifying the "input file" and its path :
input {
  file {
    path => "/var/log/nginx/access.log"
    start_position => "beginning"
    sincedb_path => "/dev/null"
  }
}
# Filter with our "grok Pattern", specifying the directory, "/etc/logstash/patttern" : 
filter {
    grok {
      patterns_dir => ["/etc/logstash/pattern"]
      match => { "message" => "%{IPORHOST:clientip} %{NGUSER:ident} %{NGUSER:auth} \[%{HTTPDATE:timestamp}\] \"%{WORD:verb} %{URIPATHPARAM:request} HTTP/%{NUMBER:httpversion}\" %{NUMBER:response}" }
    }
}



# Specifying the "Network address and port" of our "ElasticSearch Server" as the output channel. We're also naming our index in this format, for e.g, "nginx-2023-06-05"
output {
  elasticsearch {
      hosts => ["192.168.2.18:9200"]
      index => "nginx-%{+YYYY.MM.dd}"
  }
}

>>>>>>>>



# Note: The indices will not show as of yet on the "Stack Management", precisely Index Management, but we may perform a "Curl Test" to check if the "nginx tunnel" is "transceiving" the information to our ElasticSearch Server. 



# Curl command("GET" Method request) on the ElasticSearch Server  ; 


  $ curl -v http://192.168.2.18:9200


                                                                                                                                             
┌──(root㉿kali)-[/etc/logstash/pattern]                                                                  

└─# curl -v http://192.168.2.18:9200                                  
*   Trying 192.168.2.18:9200...                                       
* Connected to 192.168.2.18 (192.168.2.18) port 9200 (#0)             
> GET / HTTP/1.1                                    
> Host: 192.168.2.18:9200                                                                               
> User-Agent: curl/7.88.1                           
> Accept: */*                                       
>                                                   
< HTTP/1.1 200 OK                                   
< X-elastic-product: Elasticsearch                  
< Warning: 299 Elasticsearch-7.17.0-bee86328705acaa9a6daede7140defd4d9ec56bd "Elasticsearch built-in security features are not enabled. Without authentication, your cluster could be accessible to anyone. See ht
tps://www.elastic.co/guide/en/elasticsearch/reference/7.17/security-minimal-setup.html to enable security."
< content-type: application/json; charset=UTF-8                                                         
< content-length: 547                                                                                   
<                                                                                                       
{                                                   
  "name" : "elasticsearch",                         
  "cluster_name" : "docker-cluster",                                                                     
  "cluster_uuid" : "8r2Tq1kZTki7bhoGH4K_BQ",                                                             
  "version" : {                                     
    "number" : "7.17.0",                            
    "build_flavor" : "default",                     
    "build_type" : "docker",                        
    "build_hash" : "bee86328705acaa9a6daede7140defd4d9ec56bd",                                           
    "build_date" : "2022-01-28T08:36:04.875279988Z",                                                     
    "build_snapshot" : false,                       
    "lucene_version" : "8.11.1",                    
    "minimum_wire_compatibility_version" : "6.8.0",                                                     
    "minimum_index_compatibility_version" : "6.0.0-beta1"                                                
  },                                                
  "tagline" : "You Know, for Search"                                                                     
}                                                   



# Note : The "Curl" test onto the "ElasticSearch Server" Succeeded !! 


# We'll now verify the directory, "/var/log/nginx/acess.log", to observe if there is any log present for `Curl test" which we've launched, this will give us the reassurance or a "Proof Of Concept" that our Nginx Tunnel works ;



  $ less  /var/log/nginx/access.log


# Unfortunately, /var/log/nginx/access.log has no pertaining "Curl Test logs", which means that there could be an issue with the "Logstash Server".


- Let"s keep investigating on this issue ...   



# Quick hint : In order to resolve this "Logstash issue", we'll first take a look at the "filebeat.yml configuration file, Outputs Section", here below ; 



# ================================== Outputs ===================================

# Configure what output to use when sending the data collected by the beat.

# ---------------------------- Elasticsearch Output ----------------------------
output.elasticsearch:
  # Array of hosts to connect to.
  hosts: ["192.168.2.18:9200"]

  # Protocol - either `http` (default) or `https`.
  #protocol: "https"

  # Authentication credentials - either API key or username/password.
  #api_key: "id:api_key"
  #username: "elastic"
  #password: "changeme"

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




              ******//// Resolving the Logstash Server issue *****/////////



# Take a look at the "logstash-plain.log" ; 


  $ sudo tail  -f /var/log/logstash/logstash-plain.log


# The connection is being refused, as "Logstash" tries to connect to the "Elasticsearch Server" : 


[2023-06-05T23:54:41,609][WARN ][logstash.outputs.elasticsearch][main] Attempted to resurrect connection to dead ES instance, but got an error {:url=>"http://127.0.0.1:9200/", :exception=>LogStash::Outputs::ElasticSearch::HttpClient::Pool::HostUnreachableError, :message=>"Elasticsearch Unreachable: [http://127.0.0.1:9200/][Manticore::SocketException] Connect to 127.0.0.1:9200 [/127.0.0.1] failed: Connection refused (Connection refused)"}





                      ********////// Enrol in Fleet - Setting up System Integration + Elastic Agent on Elastic Cloud /////************



- Verifying our deployments : 

# From "Management", move to the "Fleet" option, and wait for any "Host", to be pulled up. 


# Add an agent, which will report live logging information of our "Windows System" to the " ELasticStack Server host", so this may be viewable on Kibana. 


Important : Check if there are any logging information being fed into the "ElasticSearchServer host" by selecting the "Ingest Overview Metrics". 


# Ingest Overview Metrics : This would let us know if there is any integration working in the background, if you're being offerred the option to add "an Integration", then proceed with it.




# As a best practice, after having installed the "System integration", head straight to the "Observability Menu", then select "Stream or Logs", to ensure that there are logs being pulled to the "ElasticSearch Server".


- Note : In order to check if our "System Integration" requires an "agent", let's first head to the "Management option", then select "Integration", from there, it will let you know if it is missing an agent. 






          ********//// Working with ElasticCloud - Uninstalling and Re-installing the Cloud-ELastic Agent on Windows Host Machine ********///////



# We will need to uninstall the "Elastic Agent" then "re-install" it back again, as our package signature has not yet been verified since our "2nd deployment" through  Azure. 



- Let's first proceed to "stop" the "Elastic Agent Service" through "Command Prompt" : 



C:\Program Files\Elastic\Agent>sc stop elastic-agent

[SC] OpenService FAILED 1060:

>>>> The specified service does not exist as an "installed service".


# Since, we'll be uninstalling the service, "elastic-agent", so we'll "cd" into the "C:\Program Files\Elastic\Agent", and from there we will run the "command" below : 



C:\Program Files\Elastic\Agent>.\elastic-agent.exe uninstall

Elastic Agent will be uninstalled from your system at C:\Program Files\Elastic\Agent. Do you want to continue? 
[Y/n]:y


>>>>> Elastic Agent has been uninstalled.

# Note : The "Elastic-Agent" Service, should be "uninstalled" quite easily, only if, the service has been stopped completely. ( If the service cannot be stopped, then press "Windows Key + r", head to "services.msc", and change the "Startup type" to "manual" )



  # Execute these "Scripts", using "Powershell", however, just make sure to adjust the ExecutionPolicy, which could be currently set to, "Restricted". 





  # First, we'll need to go into this "directory", where our "Elastic Service" will be installed ; 



PS C:\Program Files> Set-ExecutionPolicy Unrestricted



# Next up, let's run the command below, in order to download our "zip containing Elastic File" ; 

PS C:\Program Files> Invoke-WebRequest -Uri https://artifacts.elastic.co/downloads/beats/elastic-agent/
elastic-agent-8.8.0-windows-x86_64.zip -OutFile elastic-agent-8.8.0-windows-x86_64.zip



  # Let's extract the "elastic-agent-8.8.0-windows-x86_64.zip file" : 


PS C:\Program Files> Expand-Archive .\elastic-agent-8.8.0-windows-x86_64.zip -DestinationPath .



# Good !!, this has been extracted, here we'll "cd" and install "elastic-agent", with our corresponding "enrollment-token" : 




# Note : Preferably run the installation as well as the enrollment, with "Command-Prompt" ;



# "cd" into the directory : 


C:\Program Files> cd .\elastic-agent-8.8.0-windows-x86_64






# Running the installation : 

C:\Program Files\elastic-agent-8.8.0-windows-x86_64>.\elastic-agent.exe install --url=https://b5615bea7f8542c78457d54d3e20e504.fleet.eastus2.azure.elastic-cloud.com:443 --enrollment-token=SkpIN2pJZ0J2NWFYek1CbVJqZlA6VmFoZExWTzFUeWFxc0xpcVpmTDB5QQ==

 >>>>> Elastic Agent will be installed at C:\Program Files\Elastic\Agent and will run as a service. Do you want to continue? [Y/n]: y 




- Note : This may take some time so please be patient ... 


# Finally this starts enrolling  >>> {"log.level":"info","@timestamp":"2023-06-07T20:04:33.813-0400","log.origin":{"file.name":"cmd/enroll_cmd.go","file.line":478},"message":"Starting enrollment to URL: https://b5615bea7f8542c78457d54d3e20e504.fleet.eastus2.azure.elastic-cloud.com:443/","ecs.version":"1.6.0"}

>>>>>> {"log.level":"info","@timestamp":"2023-06-07T20:08:34.643-0400","log.origin":{"file.name":"cmd/enroll_cmd.go","file.line":276},"message":"Successfully triggered restart on running Elastic Agent.","ecs.version":"1.6.0"}

>>>> Successfully enrolled the Elastic Agent.

>>> Elastic Agent has been successfully installed.







# Lastly verify from "services.msc", that elasticagent is "running" ... 





                                            *******///// Uninstalling and  Re-installing filebeat using a .gzip file  ********/////



# Letely, we've been experiencing numerous issues with filebeat, not loading fully as we try to run the following : 


  $ filebeat setup -e 




# Uninstallation of the "previous filebeat" version : 


┌──(root㉿kali)-[/home/kali]

└─# service filebeat stop        



# Removing all the "filbeat" components : 

┌──(root㉿kali)-[/home/kali]


└─# sudo rm -rf /usr/share/filebeat
                                       


# Removing all the filbeat configuration : 

    $ sudo rm -rf /etc/filebeat




# The best option offers to us, would be to "uninstall the existing package" and use the "link" below to load in the new ".gzip filebeat package" for installation ;




# Curl Function to download the "filebeat.*.tar.gx" file ; 


   $ curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.17.10-linux-x86_64.tar.gz



- Let`s proceed with unpacking this "filebeat .gzip file" : 



┌──(root㉿kali)-[/opt]

└─# tar -xzf filebeat-7.17.10-linux-x86_64.tar.gz




# Move into the extracted Directory : 


┌──(root㉿kali)-[/opt]

└─# cd  filebeat-7.17.10-linux-x86_64 
                                                


# We'll now move the "extracted filebeat files" to its appropriate location : 


┌──(root㉿kali)-[/opt/filebeat-7.17.10-linux-x86_64]                  

└─# ls           

fields.yml  filebeat  filebeat.reference.yml  filebeat.yml  kibana  LICENSE.txt  module  modules.d  NOTICE.txt  README.md        



# Copying the extracted Filebeat files : 


┌──(root㉿kali)-[/opt/filebeat-7.17.10-linux-x86_64]

└─# sudo cp -R * /usr/share/filebeat        




# Let's "mkdir" a directory named "/etc/filebeat", and create a "filebeat.yml file" within this path : 



  $ mkdir /etc/filebeat



# Create a "file" named filebeat.yml (Simply "copy and paste" the same "configuration filebeat.yml" from previous installation) : 


  $ gedit filbeat.yml



# We're now good to run "filebeat" :



  $ service filebeat start



  # Then let's run the "filebeat" setup :


- Let's head into the "filebeat" directory, and use the "filbeat package or software", to setup filebeat : 


    $ cd  /usr/share/filebeat 



# Here we're finally , with the setup ;


    $ ./filebeat setup -e 


Setting up ML using setup --machine-learning is going to be removed in 8.0.0. Please use the ML app instead.
See more: https://www.elastic.co/guide/en/machine-learning/current/index.html
It is not possble to load ML jobs into an Elasticsearch 8.0.0 or newer using the Beat.
2023-06-07T14:51:48.696-0400    INFO    [esclientleg]   eslegclient/connection.go:105   elasticsearch url: http://192.168.2.18:9200
2023-06-07T14:51:48.699-0400    INFO    [esclientleg]   eslegclient/connection.go:285   Attempting to connect to Elasticsearch version 7.17.0
2023-06-07T14:51:48.699-0400    INFO    kibana/client.go:180    Kibana url: http://192.168.2.18:5601
2023-06-07T14:51:48.743-0400    WARN    fileset/modules.go:463  X-Pack Machine Learning is not enabled
Loaded machine learning job configurations
2023-06-07T14:51:48.744-0400    INFO    [esclientleg]   eslegclient/connection.go:105   elasticsearch url: http://192.168.2.18:9200
2023-06-07T14:51:48.748-0400    INFO    [esclientleg]   eslegclient/connection.go:285   Attempting to connect to Elasticsearch version 7.17.0
2023-

>>>> 06-07T14:51:48.748-0400    INFO    cfgfile/reload.go:262   Loading of config files completed.

>>>> Loaded Ingest pipelines



# This does load the "config files", along with the dashboards and "filebeat-7.17.10-2023.06.07-*" indices.





# Always make sure that your filebeat.yml "inputs and config modules section" of the configuration file is properly set with respect to the below : 



filebeat.inputs:
- type: filestream
  id: my-filestream-id
 
 >>>>> enabled: true
  paths:
    - /var/log/*.log

filebeat.config.modules:
  
  path: ${path.config}/modules.d/*.yml
 >>>> reload.enabled: false

setup.template.settings:
  index.number_of_shards: 1
 



                        *******//// Testing filebeat - Good way to test the pipelines ********/////


# For testing purposes we may also run "filebeat" by creating a "tmp Directory" ; 


# Creating a tmp directory ; 
  
  
    $ mkdir tmp 


    $ cd tmp 


# Then download the custom output file, "-O", with redirection allowed, "-L" from the URL below ; 


    $ curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.17.10-linux-x86_64.tar.gz




# Let's extract the "filebeat-7.17.10-linux-x86_64.tar.gz" file : 


    $ tar xzvf filebeat-7.17.10-linux-x86_64.tar.gz 
    


# Once extracted, open the directory container filebeat : 

┌──(root㉿kali)-[~/tmp]

└─# cd filebeat-7.17.10-linux-x86_64                                



# Remember to copy "filebeat.yml" into the "new directory", such that the "setup" knows where to refer for the "filebeat configuration file" ; 


┌──(root㉿kali)-[~/tmp/filebeat-7.17.10-linux-x86_64]

└─# ls 

fields.yml  filebeat*  filebeat.reference.yml  filebeat.yml  kibana/  LICENSE.txt  module/  modules.d/  NOTICE.txt  README.md
                                                                                                                                                                          
# Edit `filebeat.yml`, for this to reflect our "previously applied filebeat configuration", and only change the "kibana and elasticsearch hosts", then run the setup as follows ; 


    $ ./filebeat setup -e



Loading dashboards (Kibana must be running and reachable)                                                                                   
2023-06-07T18:17:25.060-0400    INFO    kibana/client.go:180    Kibana url: http://192.168.2.18:5601                                        
2023-06-07T18:17:31.994-0400    INFO    kibana/client.go:180    Kibana url: http://192.168.2.18:5601                                        
 2023-06-07T18:19:17.408-0400   INFO    instance/beat.go:881    Kibana dashboards successfully loaded.                                      



>>> Loaded dashboards                                                                                                                           

2023-06-07T18:19:17.408-0400    WARN    [cfgwarn]       instance/beat.go:606  DEPRECATED: Setting up ML using Filebeat is going to be remove
d. Please use the ML app to setup jobs. Will be removed in version: 8.0.0                                                                   
Setting up ML using setup --machine-learning is going to be removed in 8.0.0. Please use the ML app instead.                                
See more: https://www.elastic.co/guide/en/machine-learning/current/index.html                                                               
It is not possble to load ML jobs into an Elasticsearch 8.0.0 or newer using the Beat.                                                      
2023-06-07T18:19:17.408-0400    INFO    [esclientleg]   eslegclient/connection.go:105  elasticsearch url: http://192.168.2.18:9200          
2023-06-07T18:19:17.447-0400    INFO    [esclientleg]   eslegclient/connection.go:285  Attempting to connect to Elasticsearch version 7.17.0
2023-06-07T18:19:17.450-0400    INFO    kibana/client.go:180    Kibana url: http://192.168.2.18:5601                                        
2023-06-07T18:19:17.663-0400    WARN    fileset/modules.go:463  X-Pack Machine Learning is not enabled                                      

>>> Loaded machine learning job configurations                                                                                                  

2023-06-07T18:19:17.727-0400    INFO    [esclientleg]   eslegclient/connection.go:105  elasticsearch url: http://192.168.2.18:9200          
2023-06-07T18:19:17.751-0400    INFO    [esclientleg]   eslegclient/connection.go:285  Attempting to connect to Elasticsearch version 7.17.0
2023-06-07T18:19:17.752-0400    INFO    cfgfile/reload.go:262   Loading of config files completed.                                          
 
 >>>> Loaded Ingest pipelines                                                                                                                     


# The setup went through successfully. 




                          /////******** Installing Filebeat Docker ********/////


# We'll now discover, how to quickly deploy a filebeat docker container, and get this to connect with the "Kibana and ElasticSearch Instances". 



# Let's run "docker pull" ; 


┌──(root㉿kali)-[/opt]
└─#                   
                                          
  $ docker pull docker.elastic.co/beats/filebeat:7.17.10                                          
                                          
7.17.10: Pulling from beats/filebeat
Digest: sha256:cf7e9080de9b6413a072535aac07a6e1c690cf0d8c500be7a76225d47e89c30a
Status: Image is up to date for docker.elastic.co/beats/filebeat:7.17.10
docker.elastic.co/beats/filebeat:7.17.10


# We're good to run the filebeat setup, but make sure that for "Kibana and the ElasticSearch" Instances, the "network.hosts" would need to be set at "192.168.2.18" as in the following below ; 


- Here is the "template for the adjusted network.hosts", for each instance ; 
                                      

# $   docker run \            
docker.elastic.co/beats/filebeat:7.17.10 \                                           
setup -E setup.kibana.host=192.168.2.18:5601 \                                       
-E output.elasticsearch.hosts=["192.168.2.18:9200"]                                  





Overwriting ILM policy is disabled. Set `setup.ilm.overwrite: true` for enabling.    

 >>>>> Index setup finished.       

 >>>> Loading dashboards (Kibana must be running and reachable)                            
 >>>>> Loaded dashboards                                                                    
Setting up ML using setup --machine-learning is going to be removed in 8.0.0. Please use the ML app instead.                                                              
See more: https://www.elastic.co/guide/en/machine-learning/current/index.html        
It is not possble to load ML jobs into an Elasticsearch 8.0.0 or newer using the Beat. 

>>>>> Loaded machine learning job configurations                   
>>>>> Loaded Ingest pipelines                   
                                 




               ********//// Installing a "fleet Managed ElasticSearch Stack" ****/////


# To begin with, we will "uninstall" our "Elasticsearch" as we want to start "afresh" ;



  $ sudo systemctl stop elasticsearch



# Remove ElasticSearch : 


  $ sudo apt-get remove elasticsearch 



  libnginx-mod-http-xslt-filter libnginx-mod-mail libnginx-mod-stream
  libnginx-mod-stream-geoip libodbc2 libodbcinst2 libogdi4.1 libpoppler123
  libproj25 libprotobuf23 libpython3.10 libpython3.10-dev
  libpython3.10-minimal libpython3.10-stdlib librpmbuild9 librpmsign9
  librttopo1 libspatialite7 libsuperlu5 libsz2 libtiff5 liburiparser1
  libwinpr2-2 libxerces-c3.2 libzxingcore1 linux-image-6.0.0-kali3-amd64
  linux-image-6.1.0-kali5-amd64 medusa nginx-core php8.1-mysql proj-bin
  proj-data python-odf-doc python-odf-tools python-pastedeploy-tpl
  python-tables-data python3-aioredis python3-ajpy python3-alabaster
  python3-apscheduler python3-bottleneck python3-commonmark python3-docutils
  python3-git python3-gitdb python3-imagesize python3-ipy python3-numexpr
  python3-odf python3-pandas python3-pandas-lib python3-pyexploitdb


..

# Remove all the ElasticSearch Configuration, "/etc/elasticsearch", and data directories, "/var/lib/elasticsearch" : 



    $ sudo rm -rf /etc/elasticsearch /var/lib/elasticsearch 





# In case, there may have been any "ElasticSearch Plugins" installed  : 



  $ sudo rm -rf /usr/share/elasticsearch/plugins



  $ sudo rm -rf /usr/share/elasticsearch/




#  Thereafter, completely remove `elasticsearch` with the below command : 


    $ sudo apt-get remove --purge elasticsearch

                                                                             
Reading package lists... Done                                            
Building dependency tree... Done
Reading state information... Done
The following packages were automatically installed and are no longer required:
  bluez-firmware catfish debugedit dh-elpa-helper docutils-common figlet finger firebird3.0-common firebird3.0-common-doc firmware-ath9k-htc
  firmware-atheros firmware-brcm80211 firmware-intel-sound firmware-iwlwifi firmware-libertas firmware-realtek firmware-sof-signed



# Finally, clear the `package` cache : 


  $ sudo apt-get clean




# We'll now `reinstall` "Elasticsearch" : 



1.  # Download and install the `public signing key` : 

  $ wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg




2. # Install `apt-transport-https` : 


  $ sudo apt-get install apt-transport-https


3. # Save and add in the new `repository definition`, and right after, make sure that there're no `conflicting apt source list` other than the `elastic-8.x.list` : 


 $ echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list


┌──(root㉿kali)-[/etc/apt/sources.list.d]                                                                                                         
└─# ls -larh                                                             

total 16K                                                                
-rw-r--r-- 1 root root  120 Jun 22 22:33 elastic-8.x.list
-rw-r--r-- 1 root root  135 May 16 14:33 docker.list
drwxr-xr-x 8 root root 4.0K May 18 11:22 ..                                                                                                       
drwxr-xr-x 2 root root 4.0K Jun 22 22:36 .


# Remove the `docker.list` : 


┌──(root㉿kali)-[/etc/apt/sources.list.d]

└─# rm docker.list      



3. # Update the packages : 


  $  sudo apt-get update 

Hit:1 http://kali.download/kali kali-rolling InRelease
Hit:2 https://artifacts.elastic.co/packages/8.x/apt stable InRelease




4. # Installing the `Elasticsearch` debian package : 

  $ sudo apt-get update && sudo apt-get install elasticsearch

  Reading package lists... Done                                                                                                             
Reading package lists... Done       
Building dependency tree... Done                                         
Reading state information... Done
The following packages were automatically installed and are no longer required:            


...............





# We shall now check if this has been properly `installed` :



┌──(root㉿kali)-[/usr/share/elasticsearch/bin] 


└─# dpkg -s elasticsearch                                                                                                                         

Package: elasticsearch                                                   
Status: install ok installed                                             
Priority: optional                                                       
Section: web                                                             
Installed-Size: 1207066                                                  
Maintainer: Elasticsearch Team <info@elastic.co>                         
Architecture: amd64                                                      
Source: elasticsearch                                                    
Version: 8.8.1                    



# Pay particular `attention` to the following below : 

┌──(root㉿kali)-[/usr/share/elasticsearch/bin]

└─# elasticsearch --version     

>>>>>>>>> elasticsearch: command not found
                                        
# This imply that elasticsearch may not be in the system's binary `executable path` : 





# Let's double check if the same `--version command` can be run from its `executable path location` :



┌──(root㉿kali)-[/usr/share/elasticsearch/bin]


└─# /usr/share/elasticsearch/bin/elasticsearch --version

warning: ignoring JAVA_HOME=/usr/lib/jvm/java-1.17.0-openjdk-amd64; using bundled JDK
Version: 8.8.1, Build: deb/f8edfccba429b6477927a7c1ce1bc6729521305e/2023-06-05T21:32:25.188464208Z, JVM: 20.0.1



# Let's add elasticsearch to the `executable path location : /usr/share/elasticsearch/bin/elasticsearch` : 


  $ export PATH=/usr/share/elasticsearch/bin:$PATH




# Since the `source configuration file`, of the `elasticsearch.seervice` has been recently changed, so run `systemctl daemon-reload` :


    $ systemctl daemon-reload 





# After having run `daemon-reload`, proceed with `enabling` elasticsearch and `starting` it `altogether` :


- Enable the service : 


    $ systemctl  enable elasticsearch



- Start the service : 


    $ systemctl start elasticsearch





                      *********** ////// {ElasticSearch - Version 8.8} - Using `Elasticsearch-certutil tool` - Create CA  + Private Key + {http.ssl.certificate + transport.ssl.certificate} ////////************


# This will allow us to secure the communication to an "encrypted ssl channel", on both `HTTP layer and the Transport layer`. 


- First of all, it's imperative to `download the configuration file` for creating the `certificates`, named `instances.yml`, then slightly `modify` and `add` in our `network address`, under the `ip section`, such as `ip: "192.168.2.18` ; 



  $ curl -so /usr/share/elasticsearch/instances.yml https://packages.wazuh.com/4.4/tpl/elastic-basic/instances_aio.yml


>>>>>>>>>>>>>>>>>>>>

instances:  
- name: "elasticsearch"
  ip:
  - "192.168.2.18"
  

>>>>>>>>>>>>>>>>>>>>>>




# This time around we would need to download the ` Elasticsearch Configuration File`, for our `Elasticsearch Server`, to initiate its `security parameters`, `network parameters` on `start up`. 



After executing this command, this file will be `outputted` as `elasticsearch.yml`, at the following `directory path location`, as `/etc/elasticsearch/elasticsearch.yml` : 



    $ curl -so /etc/elasticsearch/elasticsearch.yml https://packages.wazuh.com/4.4/tpl/elastic-basic/elasticsearch_all_in_one.yml




# Here's our `elasticsearch.yml file`, where we've added a few lines to better represent our `network.host`, as well as the `http.port : 9200`, and finally, we've modified the `path directory, of the certficates, CA - Certificate Authorities, Private keys`  : 




>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>


network.host: 192.168.2.18

http.port: 9200

node.name: elasticsearch
cluster.initial_master_nodes: elasticsearch



# Transport layer
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate


# Here we've modified the `directory location` of each as pointed out by the `indentation` : 

 >>>>>>>>> xpack.security.transport.ssl.key: /etc/elasticsearch/certs/elasticsearch.key

>>>>>> xpack.security.transport.ssl.certificate: /etc/elasticsearch/certs/elasticsearch.pem

>>>>>>>>> xpack.security.transport.ssl.certificate_authorities: /etc/elasticsearch/certs/ca/elastic-stack-ca.crt



# HTTP layer
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.verification_mode: certificate


# Similarly to the `Transport Layer Section`, we'll be adding the same `path directory location` to the `xpack.security.http.ssl` section. 


>>>>>>> xpack.security.http.ssl.key: /etc/elasticsearch/certs/elasticsearch.key
>>>>>
>>>>>>> xpack.security.http.ssl.certificate: /etc/elasticsearch/certs/elasticsearch.pem
>>>>>
>>>>>>> xpack.security.http.ssl.certificate_authorities: /etc/elasticsearch/certs/ca/elastic-stack-ca.crt

# Elasticsearch authentication
xpack.security.enabled: true

path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch


>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>








                                      ////////**************  Using elasticsearch-certutil tool - Creating elastic-stack-ca.p12 + elasticsearch.p12 ********************////////


# Since we're running `elasticsearch version ; 8.8`, so please follow the steps below to create the `corresponding certificates and keys required to communicate  with elasticsearch node using SSL`.




- To begin with, we'll be creating the `Certficate-Authority` : 



# Here we're using elasticsearch-certutil : 
  
  
          $ bin/elasticsearch-certutil ca


# After running the `command above`, this will generate the CA, named `elastic-stack-ca.p12` with extension, `.p12`. 








                                    ***************///// Creating the elasticsearch.p12 ************/////////



# Note : Our next step, will involve using `CA-elastic-stack-ca.p12`, Certificate authority, to create a `Private Key` and  the `SSL X.509 certficate`. 




- Provide the `path location for our instances.yml, CA - elastic-stack-ca.p12`, and where you want to output the `single elastcicsearch.p12, PKCS#12(.p12) file, containing the "instance SSL certificate" as well as the instance "private key" `.


┌──(root㉿kali)-[/usr/share/elasticsearch/bin]            


└─# ./elasticsearch-certutil cert --silent --in  /usr/share/elasticsearch/instances.yml --out /usr/share/elasticsearch/test1.zip --ca /usr/share/e

lasticsearch/elastic-stack-ca.p12                                                          



warning: ignoring JAVA_HOME=/usr/lib/jvm/java-1.17.0-openjdk-amd64; using bundled JDK                                                             


# Enter in the `same password enterred in previously for the "CA-Certificate Authority Creation"` : 

Enter password for CA (/usr/share/elasticsearch/elastic-stack-ca.p12) :                                                                           

# Create a `new password` for the `newly created file` : 

Enter password for elasticsearch/elasticsearch.p12 :      





# Proceed with `unzipping` the `elasticsearch.p12 file`, as soon as this would have been `outputted` as the `test1.zip`, under the path directory, `/usr/share/elasticsearch/test1.zip` : 



    $ unzip /usr/share/elasticsearch/test1.zip

Archive:  test1.zip                                                                                                                               
replace elasticsearch/elasticsearch.p12? [y]es, [n]o, [A]ll, [N]one, [r]ename: yes                                                                
  inflating: elasticsearch/elasticsearch.p12                   





# Move the corresponding `elasticsearch.p12`, to the following our `designated directory : /etc/elasticsearch/certs` : 



# If the `/certs` directory, was not yet created, then `run` the `command` below : 



- This will create the `non-existing parent directory, .../certs/ca`, include the `-p option`, for `parent directory` : 



  $ mkdir /etc/elasticsearch/certs/ca -p 



# Move the `combined {"private key + ssl.certificate"}, elasticsearch.p12`, and the `CA -Certificate Authorities, elastic-stack-ca.p12`


┌──(root㉿kali)-[/usr/share/elasticsearch/elasticsearch]

└─# ls                              

elasticsearch.p12                   
                                                                         


# Move elasticsearch.p12 : 


┌──(root㉿kali)-[/usr/share/elasticsearch/elasticsearch]


└─# mv elasticsearch.p12 /etc/elasticsearch/certs        




# Move elastic-stack-ca.p12 : 

┌──(root㉿kali)-[/usr/share/elasticsearch]                          

└─# mv elastic-stack-ca.p12 /etc/elasticsearch/certs/ca                                                                                           






          **********////// Extracting the `ssl.certificate : elasticsearch.pem`  + `Private key :  from elasticsearch.p12` *********///////



# Ultimately, after having extracted, `ssl.certificate : elasticsearch.pem, ssl.key : elasticsearch.key and the ssl.certificate_authorities : elastic-stack-ca.crt `, reference this within the following `section of our elasticsearch.yml file` as shown below ;




>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

# Transport layer


xpack.security.transport.ssl.enabled: true

xpack.security.transport.ssl.verification_mode: certificate


# Add in the `private key`, path location : 


xpack.security.transport.ssl.key: /etc/elasticsearch/certs/elasticsearch.key


# Add in the `ssl.certificate`, path location : 


xpack.security.transport.ssl.certificate: /etc/elasticsearch/certs/elasticsearch.pem


# Add in the `ssl.certficate_authorities : elastic-stack-ca.p12`, path location : 


xpack.security.transport.ssl.certificate_authorities: /etc/elasticsearch/certs/ca/elastic-stack-ca.crt






# HTTP layer


xpack.security.http.ssl.enabled: true

xpack.security.http.ssl.verification_mode: certificate


# Add in the `private key`, path location : 


xpack.security.http.ssl.key: /etc/elasticsearch/certs/elasticsearch.key

# Add in the `ssl.certificate`, path location : 


xpack.security.http.ssl.certificate: /etc/elasticsearch/certs/elasticsearch.pem


# Add in the `ssl.certficate_authorities : elastic-stack-ca.p12`, path location : 


xpack.security.http.ssl.certificate_authorities: /etc/elasticsearch/certs/ca/elastic-stack-ca.crt


>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>






# Important : `Execute` each of the `command` below, in their respective directories, `/etc/elasticsearch/certs/ca` : 





1. # Extracting the `private key : elasticsearch.key` from the `elasticsearch.p12` and convert into the `.key format` : 


# Execute this command to "extract", `private key`: 


      $ openssl pkcs12 -in elasticsearch.p12 -nocerts -nodes -out elasticsearch.key





2. # Extracting the `ssl.certificate` from the `elasticsearch.p12` and convert into the `.pem format` : 


# Execute this command to "extract", the `ssl.certificate`


      $ openssl pkcs12 -in elasticsearch.p12 -out elasticsearch.pem -clcerts -nokeys



3. # Extracting the `CA-Certficate Authorities` from the `elastic-stack-ca.p12` and convert into the `.crt format` : 


# Execute this command to "extract", the `CA-Certificate Authorities`


      $ openssl pkcs12 -in elastic-stack-ca.p12 -nokeys -out elastic-stack-ca.crt






                                *******//// Enforcing `ownership changes + permission changes` ******/////


# At the very last step, we`ll now be enforcing the permission and ownership changes to our elasticsearch.key, elastic-stack.crt, 





# Apply the `proper permission`, using `chmod` command, as well as the new ownership, `chown -R elasticsearch:` : 


  $ chown -R elasticsearch: /etc/elasticsearch/certs


  $ chmod -R 500 /etc/elasticsearch/certs  

  
  $ chmod 400 /etc/elasticsearch/certs/ca/elastic-stack-ca.crt /etc/elasticsearch/certs/elasticsearch.pem /etc/elasticsearch/certs/elasticsearch.key




# Let's `clean up` and `remove` the `test1.zip` file : 


  $ rm -rf /usr/share/elasticsearch/test1.zip
                                                                  



# `Enable` and `start` the `ElasticSearch service` : 



# Very important, after `any configuration changes`, execute `systemctl daemon-reload` : 


  $ systemctl daemon-reload


  $ systemctl enable elasticsearch


  $ systemctl start elasticsearch






# Finally, this would allow us to `efficiently start` the `elasticsearch service`, and you could verify this by heading onto the `URL: http://192.168.2.1:9200`. 






              ********************///////// Resetting the elasticsearch password + Curl against `http://192.168.2.18:9200` **************//////////




                                                                                                                                                  
┌──(root㉿kali)-[/usr/share/elasticsearch/bin]                                                                                                    


└─# ./elasticsearch-reset-password -a  -u elastic                                                                                                 

warning: ignoring JAVA_HOME=/usr/lib/jvm/java-1.17.0-openjdk-amd64; using bundled JDK                                                             
This tool will reset the password of the [elastic] user to an autogenerated value.                                                                
The password will be printed in the console.                                                                                                      

Please confirm that you would like to continue [y/N]y                                                                                             
                                                                                                                                                  
                                                                                                                                                  
Password for the [elastic] user successfully reset.                                                                                               

New value: F232k5N51g4BJunZ_bYt     





# `Curl` against the `elasticsearch endpoint`, 



# -k : This option allows for `insecure` connections with `self-signed SSL Certificates`.


    $ curl -XGET https://192.168.2.18:9200 -u elastic:F232k5N51g4BJunZ_bYt -k




>>>>>>>>>>>>>>>>>>>>>>>>>

Output

{
  "name" : "elasticsearch",
  "cluster_name" : "elasticsearch",
  "cluster_uuid" : "CFw_rkxnR7avI7pBv9MvtQ",
  "version" : {
    "number" : "7.17.9",
    "build_flavor" : "default",
    "build_type" : "rpm",
    "build_hash" : "ef48222227ee6b9e70e502f0f0daa52435ee634d",
    "build_date" : "2023-01-31T05:34:43.305517834Z",
    "build_snapshot" : false,
    "lucene_version" : "8.11.1",

>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>





# Very quickly, let's try to change the Ip Address, of our interface, eth0, in case this would have a "different Ip Address" assigned to it ;


  $ sudo ifconfig eth0 192.168.2.28 




