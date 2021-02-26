# Fortigate SSLVPN User Revoker

Bunch of cross-platform Python scripts that are written to remove SSLVPN users from your Fortigate firewalls and store the states in a ```database``` file.

It comes in two flavors, ```SSH``` and ```API``` versions and you can pick both or either of these for your use case.

```fortidb.py``` module is called from the main programs and is used to ```log```, ```audit``` and keep ```track``` of user deletion process.

If you run ```fortidb.py``` directly, it will show you a list of users that have been given to be deleted, their status and also you get the option of viewing their group membership prior to deletion.

## Good to know

There is a function called ```sanitize_username``` in ```API``` version and a method called ```SanitizeUsername``` in ```SSH``` version that can be customized with the user format you use in your company, so that you could disregard the case-sensitivity of users upon feeding them to the scripts.

**Currently it just strips and returns what you input**.

## Requirements

```Python``` has to be installed on the machine, running the scripts.

```Paramiko```, ```Netmiko``` and ```FortiOSAPI``` are needed to run this script. You can install them using below [guide](#intsall-the-required-modules).

## Usage

Both scripts can get either a ```username``` or a ```text file``` with the users you want to delete, separated by ```newlines```. 

**Make sure of the case sensitivity of users you want to delete. They should be the same as your firewalls unless you have modified the ```sanitize_username``` or ```SanitizeUsername```**.

### Clone the repository

```bash
git clone https://github.com/pouriyajamshidi/FortiSSLVPNUserRevoker.git
```

### Intsall the required modules

```bash
pip3 install -r requirements.txt
```

### Make the scripts executable

```bash
chmod +x FortiSSLVPNRevoker-API.py
chmod +x FortiSSLVPNRevoker-SSH.py
```

### To delete a single user:

```python
./FortiSSLVPNRevoker-SSH.py <username>
OR
./FortiSSLVPNRevoker-API.py <username>
```

### To delete a bunch of users in a text file:

```python
./FortiSSLVPNRevoker-SSH.py <userlist.txt>
OR
./FortiSSLVPNRevoker-API.py <userlist.txt>
```

## If you prefer to invoke them using Python:

### To delete a single user

```python
python3 FortiSSLVPNRevoker-SSH.py <username>
OR
python3 FortiSSLVPNRevoker-API.py <username>
```

### To delete a bunch of users in a text file

```python
python3 FortiSSLVPNRevoker-SSH.py <userlist.txt>
OR
python3 FortiSSLVPNRevoker-API.py <userlist.txt>
```

## Tested on

Linux and Windows machines.

## Contributing

Pull requests are welcome.

## License

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
