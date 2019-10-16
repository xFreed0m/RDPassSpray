# RDPassSpray

RDPassSpary is a python tool to perform password spray attack in a Microsoft domain environment.
ALWAYS VERIFY THE LOCKOUT POLICY TO PREVENT LOCKING USERS.

## How to use it
First, install the needed dependencies:
```
pip3 install -r requirements.txt
```
Second, make sure you have xfreerdp:
```
apt-get install python-apt
apt-get install xfreerdp
````
Last, run the tool with the needed flags:
```
python3 RDPassSpray.py -u [USERNAME] -p [PASSWORD] -d [DOMAIN] -t [TARGET IP]
```

## Options to consider
* -p\-P
  * single password or file with passwords (one each line)
* -u\-U
  * single username or file with usernames (one each line)  
* -n
  * list of hostname to use when authenticating (more details below)
* -o
  * output file name (csv)
* -s
  * throttling time (in seconds) between attempts
* -r
  * random throttling time between attempts (based on user input for min and max values)
 
 
## Advantages for this technique
Failed authentication attempts will produce event ID 4625 ("An account failed to log on") BUT:
* the event won't have the source ip of the attacking machine:
![No source IP](https://github.com/xFreed0m/RDPassSpray/blob/master/no_src_ip.png)
* The event will record the hostname provided to the tool:
![Fake hostname](https://github.com/xFreed0m/RDPassSpray/raw/master/fake_hostname.png)

### Tested OS
Currently was test on Kali Rolling against Windows Server 2012 Domain Controller
I didn't had a full logged environment for deeper testing, if you have one, please let me know how it looks on other systems.

### Sample
![sample](https://github.com/xFreed0m/RDPassSpray/blob/master/sample.png)

### Credit
This tools is based on the POC made by @dafthack - https://github.com/dafthack/RDPSpray

### Donations
Did my work helped you? Did it saved you some time and money?
Well, just in case you want to buy me coffee (or beer), feel free to make a donation, it will be highly appreciated!

Thanks in advance!

[![Donate with Ethereum](https://en.cryptobadges.io/badge/big/0xC1c9F71cb7845D7c3254Fa6b8b968ceDb5FA1bBE)](https://en.cryptobadges.io/donate/0xC1c9F71cb7845D7c3254Fa6b8b968ceDb5FA1bBE)[![Donate with Bitcoin](https://en.cryptobadges.io/badge/big/1Nkqjt7fZ8NDJdeRKZcGKUQREoaSyLhvde)](https://en.cryptobadges.io/donate/1Nkqjt7fZ8NDJdeRKZcGKUQREoaSyLhvde)
>_If you use another crypto, please send me a message and i will pass you a specific address for that coin_

### Issues, bugs and other code-issues
Yeah, I know, this code isn't the best. I'm fine with it as I'm not a developer and this is part of my learning process.
If there is an option to do some of it better, please, let me know.

_Not how many, but where._
