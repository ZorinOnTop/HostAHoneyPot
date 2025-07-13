# HostAHoneyPot
Host a HoneyPot and report IP addresses to AbuseIPDB!

# How to install HostAHoneyPot?
If you bought and logged in to the server for the first time, update it.

```
sudo apt full-upgrade
```

<hr>

After updating system, install needed packages:
```
sudo apt install nginx python3 python3-pip python3-flask python3-requests git
```

Download HostAHoneyPot using Git:
```
git clone https://github.com/ZorinOnTop/HostAHoneyPot.git
```

Configure HostAHoneyPot:
```
nano HostAHoneyPot/main.py
```

Run HostAHoneyPot:
```
python3 HostAHoneyPot/main.py
```
