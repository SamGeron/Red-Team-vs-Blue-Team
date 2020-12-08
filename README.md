# Red-Team-vs-Blue-Team

# **NETWORK TOPOLOGY**

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Topology.png)
____________________________________________________________________________________________
### *Red Team Environment*
![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Red%20Team.png)
____________________________________________________________________________________________
### *Blue Team Environment*
![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Blue%20Team.png)

# **RED TEAM - Penetration Test**

## **EXPLOITATION**

### **Discover target IP:**

To discover the target ip:
```
netdiscover -r <ip subnet>
```

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture1.png)

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture2.png)

| IP | Machine |
|:-------------:|:-------------:|
| 192.168.1.1 | Gateway IP, Hyper-V |
| 192.168.1.100 | ELK server |
| 192.168.1.105 | Capstone, target machine |

### **Service and version scan:**

```
nmap -sV -v 192.168.1.105
```
| Port | Service | Version |
|:--:|:--:|:--:|
| Port 22 | SSH | OpenSSH 7.6p1 |
| Port 80 | HTTP | Apache httpd 2.4.29 |

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture3.png)

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture4.png)

### **Aggressive scan:**

```
nmap -A -vvv 192.168.1.105
```

A simple aggressive scan reveals a webserver directory structure on tcp port 80, which is a http port, and two potential usernames of employees – ashton and hannah (which will be more relevant for bruteforcing later):

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture5.png)

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture6.png)

### **Navigating the Webserver:**

As this is a webserver, we can investigate further from a browser in the attacker machine:

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture7.png)

In a text document the blog directory we can see a 3rd potential username – Ryan, who would potentially have the highest level access as CEO:

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture8.png)

In the _company folders_ directory, we can see reference to a &quot;_secret\_folder_&quot; in ALL documents within this directory, which is now a target for this Penetration Test.

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture9.png)

The _meet\_our\_team_ folder confirms the three potential users, and each document references the _secret\_folder:_

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture10.png)

As we can see below, we will need Ashton&#39;s password to gain access to the secure hidden folder.

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture11.png)

### **Vulnerability scan:**

```
nmap -A --script=vuln -vvv 192.168.1.105
```

Returning to scanning for further recon.

Aggressive scan with a vulnerability script reveals:

- Webdav vulnerability
- SQL Injection vulnerability across all directories on the webserver
- CVE-2017-15710 – Apache httpd vulnerability

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture12.png)

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture13a.png)

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture14.png)

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture15a.png)

### **Bruteforce:**

Now that we have some usernames and a main target - Ashton, using hydra we can attempt to bruteforce the login for the _secret\_folder_.

Ashton, the CEO, had a common password within our password list. Using the following command, we could get Ashton&#39;s password.

```
hydra -l ashton -P /opt/rockyou.txt -s 80 -f -vV 192.168.1.105 http-get "/company_folders/secret_folder"
```

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture16.png)

### **SSH:**

```
ssh ashton@192.168.1.105
```

Using Ashton's credentials we could gain ssh entry into the server.

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture17.png)

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture18.png)

In the root home directory we could pickup a flag.

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture19.png)

Using the same credentials, we could access the protected hidden folder.

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture20.png)

### **Password hash:**

Within this folder was a document with instructions to connect to a _corp\_server_. Included in the document are Ryan&#39;s hashed credentials and reference to a webdav directory

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture21.png)

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture22.png)

Th hashed md5 password was instantly cracked using Crackstation, revealing the password _linux4u_

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture23.png)

### **Webdav:**

We could then login to webdav using Ryan&#39;s credentials.

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture24.png)

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture25.png)

### **Reverse Shell:**

The next task was to upload a shell script to webdav, in order to create a reverse shell.

Using msfvenom we created a payload – shell.php

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture26.png)

Using cadaver and Ryan&#39;s credentials we accessed webdav, and uploaded the payload to the webdav directory.

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture27.png)

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture28.png)

Once the payload was successfully uploaded, in order to create the reverse shell, we setup a listener using Metasploit.

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture29.png)

After loading the exploit and activating the shell.php we uploaded earlier by clicking on it on the webserver, the target server connected to our listener and launched a meterpreter session into their system.

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture30.png)

### **Gaining Interactive Shell:**

```
python -c 'import pty; pty.spawn("/bin/bash")'
```

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture31.png)

### **Finding Flag 2:**

The next flag was located in the root directory.

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture32.png)

Exit back to meterpreter.

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture33.png)

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture34.png)

### **Exfiltration:**

The file was easily exfiltrated back to the attacker machine.

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture35.png)

![alt-text](https://github.com/SamGeron/Red-Team-vs-Blue-Team/blob/main/images/Picture36.png)


## Vulnerabilities

### Webserver

#### 1. Directory listing vulnerability. Webserver directories are open to the public and navigable in a browser.

CWE-548: Exposure of Information Through Directory Listing

[https://cwe.mitre.org/data/definitions/548.html](https://cwe.mitre.org/data/definitions/548.html)

- Attackers can gather a lot of information from open directories. They can use this information and access to launch attacks and upload malicious content. These directories may also be vulnerable to path traversal in which users can navigate across to sensitive regions of the system.
- Disable the ability to view directories in the browser, and disable access/password protect all directories to avoid path traversal. Sanitise input to avoid malicious SQL statements.

#### 2. SQL Injection. Nmap revealed a possible vulnerability to SQL injection to the directories in the webserver.

- This can allow attackers to enter malicious code and gain access or launch attacks.
- Sanitise inputs.

#### 3. Documents with usernames in plain text are available to the public in the webserver

CWE-312: Cleartext Storage of Sensitive Information

[https://cwe.mitre.org/data/definitions/312.html](https://cwe.mitre.org/data/definitions/312.html)

CWE-256: Unprotected Storage of Credentials

[https://cwe.mitre.org/data/definitions/256.html](https://cwe.mitre.org/data/definitions/256.html)

- Attackers can use this information in bruteforce attacks. Even just one name can lead to a system breach.
- Users should not be using their own names as usernames. User names should not be published anywhere, especially not a webserver.

#### 4. Documents in the webserver give direct reference to a hidden directory with sensitive data.

- These are breadcrumbs that attackers will follow, with a direct reference to a hidden directory attackers can focus attacks to access the contents of the directory.
- Do not reference sensitive directories in publicly available documents. If it is necessary to mention it, then encrypt and password protect.

#### 5. Webdav is enabled and allows uploading of malicious script.

CWE-434: Unrestricted Upload of File with Dangerous Type

https://cwe.mitre.org/data/definitions/434.html

- It is easy to create a shell in the target system using a reverse shell, by opening a meterpreter session
- Disable webdav

#### 6. Missing encryption of sensitive data.

CWE-311: Missing Encryption of Sensitive Data

[https://cwe.mitre.org/data/definitions/311.html](https://cwe.mitre.org/data/definitions/311.html)

#### 7. CWE-522: Insufficiently Protected Credentials

### Users and Passwords

#### 1. Usernames are employee first names. 
These are too obvious and most likely discoverable through Google Dorking. All are high level employees of the company which are more vulnerable, and certainly easier to find in the company structure in publicly available material.

- Attackers can (with very little investigation) create a wordlist of usernames of employees for bruteforcing.
- Usernames should not include the person&#39;s name.

#### 2. Ryan's password hash was printed into a document, publicly available on the webserver. 
The password hash is highly confidential and vulnerable once an attacker can access it.

CWE-256: Unprotected Storage of Credentials

[https://cwe.mitre.org/data/definitions/256.html](https://cwe.mitre.org/data/definitions/256.html)

- A password hash is one of the highest targets for an attacker that is trying to gain entry; being able to navigate to one in a browser through minimal effort is a critical vulnerability.
- Password hashes should remain in the /etc/shadow directory with root only access in the system, and not be published or copied anywhere.

#### 3. CWE-759: Use of a One-Way Hash without a Salt. 
[https://cwe.mitre.org/data/definitions/759.html](https://cwe.mitre.org/data/definitions/759.html)

CWE-916: Use of Password Hash With Insufficient Computational Effort

[https://cwe.mitre.org/data/definitions/916.html](https://cwe.mitre.org/data/definitions/916.html)

Ryan's password is only hashed, but not salted. A password hash can be run through apps to crack the password, however a salted hash will be almost impossible to crack.

- A simple hash can be cracked with tools in linux or through websites, in this case it took seconds to crack Ryan&#39;s hash.
- Salt hashes.

#### 4. CWE-521: Weak Password Requirements.

[https://cwe.mitre.org/data/definitions/521.html](https://cwe.mitre.org/data/definitions/521.html)

Passwords need to have a minimum requirement of password length and use of mixed characters and case.

- _linux4u_ is a simple phrase with very common word substitution – 4=for, u=you. and _leopoldo_ is a common name that could easily be bruteforced with a common password list.
- Require strong passwords that exclude phrases and names, minimum 8 characters, mixed characters that include a combination of lower case, upper case, special characters and numbers.
- Consider implementing multi-factor authentication.

### Apache 2.4.29

#### 1. CVE-2017-15710 
This potential Apache httpd vulnerability was picked up by nmap and relates to a configuration that verifies user credentials; a particular header value is searched for and if it is not present in the charset conversion table, it reverts to a fallback of 2 characters (eg. _en-US_ becomes _en_). While this risk is unlikely, if there is a header value of less than 2 characters, the system may crash.

- This vulnerability has the potential to force a Denial of Service attack.
- As this vulnerability applies to a range of Apache httpd versions from 2.0.23 to 2.4.29, upgrading to the latest version 2.2.46 may mitigate this risk.

#### 2. CVE-2018-1312 
While this vulnerability wasn&#39;t picked up in any scans, the apache version remains vulnerable. From cve-mitre &quot;_When generating an HTTP Digest authentication challenge, the nonce sent to prevent reply attacks was not correctly generated using a pseudo-random seed. In a cluster of servers using a common Digest authentication configuration, HTTP requests could be replayed across servers by an attacker without detection.&quot;_

- With this vulnerability, an attacker would be able to replay HTTP requests across a cluster of servers (that are using a common Digest authentication configuration), whilst avoiding detection.
- Apache httpd versions 2.2.0 to 2.4.29 are vulnerable - upgrade to 2.2.46

#### 3. CVE-2017-1283 
_Mod\_session is configured to forward its session data to CGI applications_

- With this vulnerability, _a remote user may influence their content by using a &quot;Session&quot; header._
- Apache httpd versions 2.2.0 to 2.4.29 are vulnerable - upgrade to 2.2.46

#### 4. CVE-2017-15715 
This vulnerability relates to malicious filenames, in which the end of filenames can be matched/replaced with &#39;$&#39;

- In systems where file uploads are externally blocked, this vulnerability can be exploited to upload malicious files
- Apache httpd versions 2.2.0 to 2.4.29 are vulnerable - upgrade to 2.2.46
