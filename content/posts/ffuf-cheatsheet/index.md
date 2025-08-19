---
title: FFuF Cheatsheet
date: 2024-08-20
toc: true
---

> *FFUF, or “Fuzz Faster you Fool” is an open source web fuzzing tool, intended for discovering elements and content within web applications, or web servers.*

## Fuzzing
### **Subdomain/VHost**

```shell
Wordlists
=========
- /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

$ ffuf -w <wordlist>:FUZZ -u https://FUZZ.<SERVER_IP>:<PORT>/ -ac
$ ffuf -w <wordlist>:FUZZ -u https://<SERVER_IP>:<PORT>/ -H "Host: FUZZ.<domain>"
```

Don't forget to add subdomains/vhosts to `/etc/hosts`

```shell
$ echo "SERVER_IP DNS_NAME" | sudo tee -a /etc/hosts
```

### **Extension**

```shell
Wordlists
=========
- /opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt

$ ffuf -w <wordlist>:FUZZ -u http://<SERVER_IP>:<PORT>/indexFUZZ -ac 
```

> To specify the extension type to append to every word in the wordlist, use the `-e` switch.
> `-e <extension1>,<extension2>,<extension3>,...`

### **Directory**

```shell
Wordlists
=========
- /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
- /opt/useful/SecLists/Discovery/Web-Content/raft-medium-directories.txt

$ ffuf -w <wordlist>:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ -ac
$ ffuf -w <wordlist>:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ -recursion -recursion-depth 1 -ac
```

### **Page**

```shell
Wordlists
=========
- /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt

$ ffuf -w <wordlist>:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php -ac
```

### **Parameter**

```shell
Wordlists
=========
- /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt

$ ffuf -w <wordlist>:FUZZ -u http://<SERVER_IP>:<PORT>/admin/admin.php?FUZZ=key -ac
$ ffuf -w <wordlist>:FUZZ -u http://<SERVER_IP>:<PORT>/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -ac
```

### **Parameter Value**

```
$ ffuf -w <wordlist>:FUZZ -u http://<SERVER_IP>:<PORT>/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -ac
```

## Tips & Tricks

Some tips & tricks I gathered by reading documentation and detailed blogs. They help you harness the tool. Like really. :grinning_face:

### **Increasing Speed**

```shell
$ ffuf -w <wordlist>:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ -t 200
```

> *By default FFUF will use 40 threads to execute.*

### **Filtering**

```shell
MATCHER OPTIONS:
  -mc              Match HTTP status codes, or "all" for everything. (default: 200,204,301,302,307,401,403)
  -ml              Match amount of lines in response
  -mr              Match regexp
  -ms              Match HTTP response size
  -mw              Match amount of words in response

FILTER OPTIONS:
  -fc              Filter HTTP status codes from response. Comma separated list of codes and ranges
  -fl              Filter by amount of lines in response. Comma separated list of line counts and ranges
  -fr              Filter regexp
  -fs              Filter HTTP response size. Comma separated list of sizes and ranges
  -fw              Filter by amount of words in response. Comma separated list of word counts and ranges
```

### **Using Multiple Wordlists**

```shell
$ ffuf -u https://W2.<SERVER_IP>:<PORT>/W1 -w <wordlist1>:W1,<wordlist2>:W2
```

**Cluster Bomb**

```shell
$ ffuf -mode clusterbomb -u https://W2.<SERVER_IP>:<PORT>/W1 -w <wordlist1>:W1,<wordlist2>:W2
```

![Visualization of Cluster Bomb](https://github.com/user-attachments/assets/cf69c470-5c26-43bb-9093-aacbba140e73)

**Pitch Fork**

```
$ ffuf -mode pitchfork -u https://W2.<SERVER_IP>:<PORT>/W1 -w <wordlist1>:W1,<wordlist2>:W2
```

![Pasted image 20241116233100](https://github.com/user-attachments/assets/77140571-4163-4eb8-9457-2b5ff66c1a9a)

### **Cookie Based Authentication**

```shell
$ ffuf -w <wordlist>:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ -b <cookies> -ac
```

### **Silent Mode 🔇**

```shell
$ ffuf -w <wordlist>:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ -ac -s
```
