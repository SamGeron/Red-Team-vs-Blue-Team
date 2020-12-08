# Red-Team-vs-Blue-Team

# **NETWORK TOPOLOGY**



# **RED TEAM**
## Penetration Test

## **EXPLOITATION**

**Discover target IP:**

To discover the target ip:

netdiscover -r

![](RackMultipart20201208-4-1xqs3pk_html_7941588c79f74b33.png) p1

![](RackMultipart20201208-4-1xqs3pk_html_cedf5d1d63b30f7f.png) p2

192.168.1.1 is the gateway ip, from Hyper-V

192.168.1.100 is the ELK server

192.168.1.105 is the target machine

**Service and version scan:**

nmap -sV -v 192.168.1.105

Port 22 – SSH - with OpenSSH 7.6p1

Port 80 – HTTP - with Apache httpd 2.4.29

![](RackMultipart20201208-4-1xqs3pk_html_c6292e6a1a8f6f30.png) p3

![](RackMultipart20201208-4-1xqs3pk_html_78d6c7d7aa59b9dd.png) p4

**Aggressive scan:**

A simple aggressive scan reveals a webserver directory structure on tcp port 80, which is a http port, and two potential usernames of employees – ashton and hannah (which will be more relevant for bruteforcing later):

![](RackMultipart20201208-4-1xqs3pk_html_f1bdb40627286b46.png) p5

![](RackMultipart20201208-4-1xqs3pk_html_bcbddb44abe4680e.gif) ![](RackMultipart20201208-4-1xqs3pk_html_4b81eb9a47271780.png) p6

**Navigating the Webserver:**

As this is a webserver, we can investigate further from a browser in the attacker machine:

![](RackMultipart20201208-4-1xqs3pk_html_f3073b14398f14a9.gif) ![](RackMultipart20201208-4-1xqs3pk_html_a6b2d942f1b25c4c.png) p7

In a text document the blog directory we can see a 3rd potential username – Ryan, who would potentially have the highest level access as CEO:

![](RackMultipart20201208-4-1xqs3pk_html_2e92984833eeaae6.png) p8

In the _company folders_ directory, we can see reference to a &quot;_secret\_folder_&quot; in ALL documents within this directory, which is now a target for this Penetration Test.

![](RackMultipart20201208-4-1xqs3pk_html_33a7aa8c633a5aff.gif) ![](RackMultipart20201208-4-1xqs3pk_html_e3e77e96f478688f.png) p9

The _meet\_our\_team_ folder confirms the three potential users, and each document references the _secret\_folder:_

![](RackMultipart20201208-4-1xqs3pk_html_5e0a83a8c4781223.gif) ![](RackMultipart20201208-4-1xqs3pk_html_f446396bd3b91940.png) p10

As we can see below, we will need Ashton&#39;s password to gain access to the secure hidden folder.

![](RackMultipart20201208-4-1xqs3pk_html_d4245b710fc193fa.gif) ![](RackMultipart20201208-4-1xqs3pk_html_ff2dc87667b7c29d.png) p11

**Vulnerability scan:**

Returning to scanning for further recon.

Aggressive scan with a vulnerability script reveals:

- Webdav vulnerability
- SQL Injection vulnerability across all directories on the webserver
- CVE-2017-15710 – Apache httpd vulnerability

![](RackMultipart20201208-4-1xqs3pk_html_5b7d1039315f0990.png) p12

![](RackMultipart20201208-4-1xqs3pk_html_4155665b12f97f60.gif) ![](RackMultipart20201208-4-1xqs3pk_html_85975e97be642379.gif) ![](RackMultipart20201208-4-1xqs3pk_html_6e3476da6cb66e32.png) p13

![](RackMultipart20201208-4-1xqs3pk_html_a48cf6f119d2e065.png) p14

![](RackMultipart20201208-4-1xqs3pk_html_db1129f5a05a0267.gif) ![](RackMultipart20201208-4-1xqs3pk_html_26f089b9205399ee.png) p15

**Bruteforce:**

Now that we have some usernames and a main target - Ashton, using hydra we can attempt to bruteforce the login for the _secret\_folder_.

Ashton, the CEO, had a common password within our password list. Using the following command, we could get Ashton&#39;s password.

hydra -l ashton -P /opt/rockyou.txt -s 80 -f -vV 192.168.1.105 http-get &quot;/company\_folders/secret\_folder&quot;

![](RackMultipart20201208-4-1xqs3pk_html_fae62275478e86aa.gif) ![](RackMultipart20201208-4-1xqs3pk_html_17ec5ee6be931c92.png) p16

**SSH:**

Using Ashton&#39;s credentials we could gain ssh entry into the server.

![](RackMultipart20201208-4-1xqs3pk_html_89d0c984e3b7a816.png) p17

![](RackMultipart20201208-4-1xqs3pk_html_5f61cc0e5b36a764.png) p18

In the root home directory we could pickup a flag.

![](RackMultipart20201208-4-1xqs3pk_html_7fe64f049c0774ff.gif) ![](RackMultipart20201208-4-1xqs3pk_html_13cc37d148272839.gif) ![](RackMultipart20201208-4-1xqs3pk_html_d0c9ea4b23ed3c46.png) p19

Using the same credentials, we could access the protected hidden folder.

![](RackMultipart20201208-4-1xqs3pk_html_b37aee0f89c0c866.png) p20

**Password hash:**

Within this folder was a document with instructions to connect to a _corp\_server_. Included in the document are Ryan&#39;s hashed credentials and reference to a webdav directory

![](RackMultipart20201208-4-1xqs3pk_html_e0a16dd0c0c6e35f.gif) ![](RackMultipart20201208-4-1xqs3pk_html_559a3722861a9978.png) p21

![](RackMultipart20201208-4-1xqs3pk_html_6ba23ae193f3da9a.gif) ![](RackMultipart20201208-4-1xqs3pk_html_d11f22b253aabf39.gif) ![](RackMultipart20201208-4-1xqs3pk_html_77dcab3edc3e3126.png) p22

Th hashed md5 password was instantly cracked using Crackstation, revealing the password _linux4u_

![](RackMultipart20201208-4-1xqs3pk_html_ff5640c3ef962af.gif) ![](RackMultipart20201208-4-1xqs3pk_html_704f1a2137146c54.png) p23

**Webdav:**

We could then login to webdav using Ryan&#39;s credentials.

![](RackMultipart20201208-4-1xqs3pk_html_4fc01347812dacb2.png) p24

![](RackMultipart20201208-4-1xqs3pk_html_b314f1e8f0a99d14.png) p25

**Reverse Shell:**

The next task was to upload a shell script to webdav, in order to create a reverse shell.

Using msfvenom we created a payload – shell.php

![](RackMultipart20201208-4-1xqs3pk_html_f14d223bac9f82d2.gif) ![](RackMultipart20201208-4-1xqs3pk_html_162b62d8c5228498.gif) ![](RackMultipart20201208-4-1xqs3pk_html_692ff9c9865d6bd0.png) **p26**

Using cadaver and Ryan&#39;s credentials we accessed webdav, and uploaded the payload to the webdav directory.

![](RackMultipart20201208-4-1xqs3pk_html_cb2cced68ec1bacd.gif) ![](RackMultipart20201208-4-1xqs3pk_html_136e540493ffd44d.png) **p27**

![](RackMultipart20201208-4-1xqs3pk_html_8821b2740ffe5594.gif) ![](RackMultipart20201208-4-1xqs3pk_html_38acf980c0c38c0f.png) **p28**

Once the payload was successfully uploaded, in order to create the reverse shell, we setup a listener using Metasploit.

![](RackMultipart20201208-4-1xqs3pk_html_8a98d39918d089f5.png) **p29**

After loading the exploit and activating the shell.php we uploaded earlier by clicking on it on the webserver, the target server connected to our listener and launched a meterpreter session into their system.

![](RackMultipart20201208-4-1xqs3pk_html_51d959a89c477186.png) **p30**

**GAINING INTERACTIVE SHELL:**

python -c &#39;import pty; pty.spawn(&quot;/bin/bash&quot;)&#39;

![](RackMultipart20201208-4-1xqs3pk_html_434692ee26e60ce9.png) p31

**FINDING THE FLAG:**

The next flag was located in the root directory.

![](RackMultipart20201208-4-1xqs3pk_html_1152c3a238566b92.gif) ![](RackMultipart20201208-4-1xqs3pk_html_497a78d8b61b69d7.png) p32

Exit back to meterpreter.

![](RackMultipart20201208-4-1xqs3pk_html_1152c3a238566b92.gif) ![](RackMultipart20201208-4-1xqs3pk_html_de9643a50261127e.png) p33

![](RackMultipart20201208-4-1xqs3pk_html_58fc958465dd43eb.png) **p34**

**EXFILTRATION:**

The file was easily exfiltrated back to the attacker machine.

![](RackMultipart20201208-4-1xqs3pk_html_77f6ff8f5c9b4751.png) **p35**

![](RackMultipart20201208-4-1xqs3pk_html_3618721709e861e2.gif) ![](RackMultipart20201208-4-1xqs3pk_html_97a557019a0b4c65.png) **p36**


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
