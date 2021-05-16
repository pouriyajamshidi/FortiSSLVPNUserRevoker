#!/usr/bin/env python3

import os
import re
import signal
import sys
import time
from os.path import isfile

from netmiko import ConnectHandler
from netmiko.ssh_exception import (AuthenticationException,
                                   NetMikoTimeoutException)
from paramiko.ssh_exception import SSHException
from yaml import safe_load

from fortidb import operate_on_DB, update_userstatus


class FortiSSLVPN():

    def __init__(self, admin_username, admin_password):
        signal.signal(signal.SIGINT, self.SignalHandler)
        self.admin_username = admin_username
        self.admin_password = admin_password
        self.file_list = []
        self.userlist = []
        self.usrdic = {}
        self.username = ""
        self.user_from_list = []
        self.dbname = "RevokedUsers.db"
        self.batchCFGfilename = "BatchRevokeCFG.txt"

    def SignalHandler(self, frame, signal):
        '''On ctrl+c, exit gracefully.'''

        print("\n[⚠️ ] Caught SIGINT\n[⚠️ ] Exiting...")
        exit(1)

    def SanitizeUsername(self, username):
        '''Format the received username
            to be like Fortigate's.'''

        return username.strip()

    def HandleInputFile(self, filename):
        '''Read received file and '''

        with open(filename, "r") as file:
            for username in file:
                username = self.SanitizeUsername(username)
                print(f"[✔️ ] Received {username}")
                self.user_from_list.append(username)

    def ChooseUsername(self, username):
        '''Check whether username is entered
            if so, pass it to SanitizeUsername()
            else, show help message.
            returns username.'''

        self.username = self.SanitizeUsername(username)

        username = self.username
        print(f"[✔️ ] Chosen {username} to query in {self.fwname}")

        return username

    def CheckLocalFile(self, devname):
        '''Checks for UserGroups file in current
            directory. If not found, fetches it.
            If more than 1 UserGroups file is
            found, SelectLocalFile() is called.'''

        CWD = os.getcwd()
        print(f"[✔️ ] Looking for {devname} file in {CWD}")

        file_pattern = re.compile(
            r"UserGroups-{}".format(devname) + r"-\d{12}.txt")

        for file in os.listdir():
            if file.endswith(".txt") and re.findall(file_pattern, file):
                if file not in self.file_list:
                    self.file_list.append(file)

        if len(self.file_list) == 0:
            print("[❌] Could not find any UserGroups file")
            user_choice = input(
                "[⚠️ ] Do you want to fetch it from firewall (y/n)? ")

            while len(user_choice) <= 0:
                user_choice = input(f"[⚠️ ] Please choose (y/n)? ")

            user_choice = user_choice.lower().strip()

            if user_choice == "n":
                exit()
            elif user_choice == "y":
                selected_file = self.GetGroupInfo()
                return selected_file

        elif len(self.file_list) == 1:
            selected_file = self.SelectLocalFile(self.file_list, devname)
            return selected_file

        elif len(self.file_list) >= 2:
            print(f"[✔️ ] Found {len(self.file_list)} UserGroup files")
            selected_file = self.SelectLocalFile(self.file_list, devname)
            return selected_file

    def SelectLocalFile(self, filelist, devname):
        '''Receives files list from CheckLocalFile(),
            displays their names and passes the
            newest one to the AssessLocalFile() '''

        print("[✔️ ] Found files are:")
        filename_dic = {}
        file_counter = 0

        for file in filelist:
            if devname in file:
                file_counter += 1
                print(f"\t{file_counter}) " + file)
                file_date = int(''.join(filter(str.isdigit, file)))
                filename_dic[file] = file_date

        selected_file = sorted(filename_dic)[-1]
        self.AssessLocalFile(selected_file)
        print(f"[✔️ ] Selected: {selected_file}")

        return selected_file

    def AssessLocalFile(self, file):
        '''Receives file name from SelectLocalFile()
            if it's older than 8 hours, asks user
            whether to fetch a new one or continue
            with current file. If user chooses
            to fetch a new UserGroups file, then
            GetGroupInfo() is called otherwise,
            the program continues with the old file.'''

        current_time = time.strftime("%Y%m%d%H%M")
        file_date = ''.join(filter(str.isdigit, file))

        calculated_time = int(current_time) - int(file_date)

        if calculated_time >= 480:
            user_choice = input(
                f"[⚠️ ] {file} is old. Do you want to fetch a new one (y/n)? ")

            while len(user_choice) <= 0:
                user_choice = input(f"[⚠️ ] Please choose (y/n)? ")

            if user_choice == "n":
                print(f"[⚠️ ] WARNING - You chose to continue with an old file")
            elif user_choice == "y":
                selected_file = self.GetGroupInfo()
                return selected_file

    def ExtractGroups(self, filename):
        '''Extracts user and group info from
            UserGroups config file and stores
             users in userlist and groups in
             usrdic. 
             ### Fix the info storage method ###
            '''

        print(f"[✔️ ] Opening {filename} for analysis.")

        with open(filename, "r") as groupfile:
            for line in groupfile:
                if "fsso" in line.lower():
                    continue
                if "edit" in line:
                    group = line.strip().replace("edit ", "").replace('"', "")
                    self.usrdic[group] = group
                if "cn=" in line.lower():
                    continue
                if "set member" in line:
                    user = line.strip().replace("set member ", "").replace('"', "").split(" ")
                    self.usrdic[group] = user
                    self.userlist.append(user)

    def DisplayGroups(self, user, filename):
        '''Passes file to ExtractGroups()
            If user is not found, exits,
            otherwise the groups will be shown
            and usrgroups list will be appended
            then it'll get returned'''

        lncounter = 0
        usrgroups = []

        self.ExtractGroups(filename)

        if not any(user in usrname for usrname in self.usrdic.values()):
            print(f"[❌] Could not locate {user} in {filename} file.")
            return

        print(f"[✔️ ] {user} is a member of:\n")
        print("-" * 40)

        for group, users in self.usrdic.items():
            if user in users:
                lncounter += 1
                print(f"{lncounter}) {group}")
                print("-" * 40)
                usrgroups.append(group)
        print("")

        return usrgroups

    def GetGroupInfo(self):
        '''SSH and get UserGroup file from firewall.
            returns filename.'''

        self.SSHtoDevice()
        print(f"[✔️ ] Gathering User and Group information from {self.fwname}")

        if self.fwvdom != "None":
            self.ssh_con.send_command(
                "config vdom", expect_string=r"#", delay_factor=1)
            self.ssh_con.send_command(
                f"edit {self.fwvdom}", expect_string=r"#", delay_factor=1)
        output = self.ssh_con.send_command(
            "show user group", expect_string=r"#", delay_factor=1)
        self.ssh_con.send_command("end", expect_string=r"#", delay_factor=1)

        print("[✔️ ] Output gathered.")

        filename = f"UserGroups-{self.fwname}-" + \
            time.strftime("%Y%m%d%H%M") + ".txt"
        print(f"[✔️ ] Saving output in {filename}.")

        with open(filename, "w") as file:
            output = file.write(output)

        return filename

    def SSHtoDevice(self):
        '''SSH to device.'''

        firewall = {
            'device_type': 'fortinet',
            'ip': self.fwip,
            'port': self.fwport,
            'username': self.admin_username,
            'password': self.admin_password,
        }

        print(f"[✔️ ] Initiating connection to {self.fwip}:{self.fwport}")

        try:
            self.ssh_con = ConnectHandler(**firewall)
            print(f"[✔️ ] Connected to {self.fwip}:{self.fwport}")
        except (AuthenticationException) as err:
            print(err)
            return 1
        except (NetMikoTimeoutException) as err:
            print(err)
            return 1
        except (EOFError) as err:
            print(err)
            return 1
        except (SSHException) as err:
            print(err)
            return 1
        except Exception as err:
            print(err)
            return 1

    def RevokeUser(self, username, groups):
        '''Sends a set of commands to revoke the user'''

        operate_on_DB(self.dbname, username, self.fwname, "Deleting", groups)

        self.SSHtoDevice()

        print(f"[✔️ ] Revoking {username} in {self.fwname}")

        if self.fwvdom != "None":
            self.ssh_con.send_command(
                "config vdom", expect_string=r"#", delay_factor=1)
            self.ssh_con.send_command(
                f"edit {self.fwvdom}", expect_string=r"#", delay_factor=1)
        self.ssh_con.send_command(
            "config user group ", expect_string=r"#", delay_factor=1)

        for group in groups:
            self.ssh_con.send_command(
                f"edit {group} ", expect_string=r"#", delay_factor=1)
            self.ssh_con.send_command(
                f"unselect member {username} ", expect_string=r"#", delay_factor=1)
            self.ssh_con.send_command(
                "next", expect_string=r"#", delay_factor=1)

        self.ssh_con.send_command("end", expect_string=r"#", delay_factor=1)
        self.ssh_con.send_command(
            "config user local ", expect_string=r"#", delay_factor=1)
        self.ssh_con.send_command(
            f"delete {username}", expect_string=r"#", delay_factor=1)
        self.ssh_con.send_command("end", expect_string=r"#", delay_factor=1)
        self.ssh_con.send_command("end", expect_string=r"#", delay_factor=1)

        update_userstatus(self.dbname, "Deleted", username, self.fwname)

        print(f"[✔️ ] Revoked {username} in {self.fwname}")

    def InitCFG(self):
        '''Create the initial config file'''

        with open(self.batchCFGfilename, "w") as cfgfile:
            cfgfile.write("config vdom\n")
            cfgfile.write(f"edit {self.fwvdom} \n")

    def GenerateCFG(self, username, groups):
        '''Config generator for device
            in case you wanna see the commands
            that are being sent'''

        with open(self.batchCFGfilename, "a") as cfgfile:
            cfgfile.write("config user group \n")

            for group in groups:
                cfgfile.write(f"edit {group} \n")
                cfgfile.write(f"unselect member {username} \n")
                cfgfile.write("next\n")

            cfgfile.write("end\n")
            cfgfile.write("config user local \n")
            cfgfile.write(f"delete {username}\n")
            cfgfile.write("end\n")

    def FinalizeCFG(self):
        '''finalize the config file'''

        with open(self.batchCFGfilename, "a") as cfgfile:
            cfgfile.write("end\n")

    def ApplyCFG(self):
        '''Sends contents of cfg file to revoke the users'''

        self.SSHtoDevice()

        print(f"[✔ ] Revoking users in {self.fwname}")

        self.ssh_con.send_config_from_file(
            self.batchCFGfilename, delay_factor=1)

        print(f"[✔ ] Revoked users in {self.fwname}")

    def UserBatch(self, users):
        '''If file is given instead of username
            then it is a batch job.
            get the list and perform revoke operation.'''

        user_list = []

        if self.fwvdom != "None":
            self.InitCFG()

        for user in users:
            username = self.ChooseUsername(user)
            filename = self.CheckLocalFile(self.fwname)
            groups = self.DisplayGroups(username, filename)

            if groups:
                user_list.append(username)
                operate_on_DB(self.dbname, username,
                              self.fwname, "Deleting", groups)
                self.GenerateCFG(username, groups)
            else:
                continue

        if user_list:
            self.FinalizeCFG()
            self.ApplyCFG()
            self.BatchUpdateDB(user_list)

    def BatchUpdateDB(self, userlist):
        '''Update status of users populated in
            UserBatch method'''

        print(f"[✔ ] Updating users status in Database")

        for user in userlist:
            print(f"[✔ ] Updating {user} in {self.fwname}")
            update_userstatus(self.dbname, "Deleted", user, self.fwname)

        print(f"[✔ ] Update completed successfully")

    def read_yaml_file(self, yamlfile):
        '''
        Open YAML file to get firewall info
        '''

        if isfile(yamlfile):
            with open(yamlfile, "r") as fwfile:
                firewalls = safe_load(fwfile)
            return firewalls
        else:
            print("Could not read firewalls.yml file")
            exit(1)

    def Run(self, user):
        '''Runs the sequence of methods required
            to revoke a user.'''

        firewalls = self.read_yaml_file("firewalls.yml")

        for fw in firewalls["firewalls"]:
            self.fwname = fw["name"]
            self.fwip = fw["mgmt_ip"]
            self.fwport = fw["port"]
            self.fwvdom = fw["vdom"]

            if isinstance(user, list):
                self.UserBatch(user)
            else:
                username = self.ChooseUsername(user)
                filename = self.CheckLocalFile(self.fwname)
                groups = self.DisplayGroups(username, filename)

                if groups:
                    self.RevokeUser(username, groups)


if __name__ == "__main__":

    def CheckAdminCreds():
        '''Get username and password
            from user and check it.'''
        import getpass
        import hashlib

        adminuser = input("[👀] Username: ").strip()
        adminpass = getpass.getpass("[🔑] Password: ").strip()
        adminpass2 = getpass.getpass("[🔑] Verify Password: ").strip()

        if len(adminuser) == 0 or len(adminpass) == 0 or len(adminpass2) == 0:
            print("[❌] Empty username or password")
            exit(1)

        pwhash1 = hashlib.md5(adminpass.encode("utf-8")).hexdigest()
        pwhash2 = hashlib.md5(adminpass2.encode("utf-8")).hexdigest()

        if pwhash1 != pwhash2:
            print("[❌] Mismatched password.\n[⚠️ ] Exiting")
            exit(1)

        return adminuser, adminpass

    def GuideUser(programname):
        print(f"[❌] Run the program like: {programname} <username>")
        print(f">>> {programname} Pouriya.Jamshidi")
        print("### OR ###")
        print(f">>> {programname} userlist.txt")
        exit(1)

    def start():
        '''Starts the program'''

        admin_username, admin_password = CheckAdminCreds()

        RevokeUser = FortiSSLVPN(admin_username, admin_password)

        programname = sys.argv[0]

        if len(sys.argv) == 1:
            GuideUser(programname)

        userinput = sys.argv[1].strip()

        if len(sys.argv) > 1 and userinput.endswith(".txt"):
            print(f"[✔️ ] Received {userinput} file as input")

            userlist = []

            with open(userinput, "r") as file:
                for username in file:
                    userlist.append(username)

            RevokeUser.Run(userlist)

        elif len(sys.argv) > 1 and len(userinput) >= 4:
            RevokeUser.Run(userinput)

    start()
