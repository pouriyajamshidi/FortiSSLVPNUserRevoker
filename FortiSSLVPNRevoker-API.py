#!/usr/bin/env python3

import logging
import signal
import sys
from os import getenv
from os.path import isfile
import requests
from fortiosapi import FortiOSAPI
from yaml import safe_load
from fortidb import operate_on_DB, update_userstatus
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def signal_handler(frame, signal):
    """
    exit gracefully on SIGINT
    """
    ENDCOLOR = '\033[0m'
    print(ENDCOLOR)
    exit()


def logger(programname):
    """
    Logs script activity to 
    """
    formatter = logging.Formatter(
        "%(asctime)s %(name)-12s %(levelname)-8s %(message)s")
    logger = logging.getLogger(f"{programname}")
    hdlr = logging.FileHandler(f"{programname}.log")
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.DEBUG)


def guide_user(programname):
    print(f"\n[❌] Run the program like: {programname} <username>")
    print(f">>> {programname} John.Smith")
    print("### OR ###")
    print(f">>> {programname} userlist.txt")
    print("\nMake sure of case sensitivity")
    exit(1)


def sanitize_username(username):
    '''
    Format the received username
    to be like the way they're defined on firewall.

    :param: username

    returns formatted username
    '''

    formatted_username = username.strip()
    print(f"[✔] Converting {username} to {formatted_username}")

    return formatted_username


def delete_user(device, userlist, groups, fwname, vdom):
    """
    deletes user(s) from firewall

    :param device: Frotigate session object
    :param userlist: list of users to delete
    :param groups: all groups to be paased to display_and_remove_user_group function
    :param fwname: delete from this device
    """

    dbname = "RevokedUsers.db"

    for user in userlist:
        print(f"[✔] Deleting {user} in {fwname}")

        user_groups = display_and_remove_user_group(device, vdom, user, groups)
        operate_on_DB(dbname, user, fwname, "Deleting", user_groups)

        data = {'name': user}
        res = device.delete('user', 'local', vdom, data=data)
        res_code = res["status"]

        if res_code == "success":
            print(f"[✔] Deleted {user} in {fwname}")
            update_userstatus(dbname, "Deleted", user, fwname)
        else:
            print("\033[1m", end="")
            print("\033[91m", end="")
            print(f"[X] Deletion of {user} in {fwname} failed")
            update_userstatus(dbname, "Failed", user, fwname)
            print("\033[32m", end="")


def display_and_remove_user_group(device, vdom, user, groups):
    """
    Displays the group(s) of a user and then passes the members
    that are NOT to be deleted to keep_users_in_group function

    Fortigate's API removes a user from a group, by 
    PUTing all the existing members but the one you 
    want to remove, back in that group.

    :param device: Fortigate object to pass to keep_users_in_group function
    :param vdom: pass to keep_users_in_group function
    :param fwname: indicate the firewall we are working on
    :param groups: and their members
    :param deletelist: list of users to be removed

    Returns the user_groups to be passed to DB
    """

    print(f"[✔] Removing {user} from their groups")

    groups_len = len(groups)
    user_groups = []
    group_counter = 0

    for i in range(groups_len):
        group_name = groups[i]["name"]
        members = groups[i]["member"]

        for member in members:
            member_name = member["name"]

            if member_name == user:
                user_groups.append(group_name)

                for i in range(len(members)):
                    if members[i]['name'] == member_name:
                        del members[i]
                        break

                keep_users_in_group(device, vdom, group_name, members)

    if user_groups:
        CYAN = "\033[1;36m"
        print(CYAN, end="")

        print(f"[✔] {user} is a member of:")
        print("-" * 75)

        for group in user_groups:
            group_counter += 1
            print(f"{group_counter}) {group}")
            print("-" * 75)

        GREEN = "\033[32m"
        print(GREEN, end="")
    else:
        print("\033[1m", end="")
        print("\033[91m", end="")
        print(f"[X] {user} is not in any groups")
        print("\033[32m", end="")

    return user_groups


def get_all_groups(device, vdom):
    """
    gets all local SSLVPN groups of firewall.
    returns groups and their members.

    :param: device to get groups from
    :param: vdom if any
    """

    print("[✔] Fetching all groups")
    groups = device.get('user', 'group', vdom=vdom)

    return groups["results"]


def find_and_remove_user_groups(device, vdom, groups, deletelist):
    """
    finds the members that are NOT to be deleted and
    passes them to keep_users_in_group function

    Fortigate's API removes a user from a group, by 
    PUTing all the existing members but the one you 
    want to remove, back in that group.

    :param device: pass to keep_users_in_group function
    :param vdom: pass to keep_users_in_group function
    :param fwname: indicate the firewall we are working on
    :param groups: and their members
    :param deletelist: list of users to be removed
    """

    print("[✔] Removing user from their groups")

    groups_len = len(groups)

    for i in range(groups_len):
        group_name = groups[i]["name"]
        members = groups[i]["member"]

        for member in members:
            member_name = member["name"]

            if member_name in deletelist:

                for i in range(len(members)):
                    if members[i]['name'] == member_name:
                        del members[i]
                        break

                keep_users_in_group(device, vdom, group_name, members)


def keep_users_in_group(device, vdom, groupname, userslist):
    """
    retains/PUTs members that are to be kept on the firewall

    Fortigate's API removes a user from a group, by 
    PUTing all the existing members but the one you 
    want to remove, back in that group.

    :param: device to pass to keep_users_in_group function
    :param: vdom to pass to keep_users_in_group function
    :param: fwname to indicate the firewall we are working on
    :param: groupname to operate on
    :param: userlist is a list of users to be kept
    """

    data = {'name': groupname, 'member': userslist}
    device.put('user', 'group', vdom=vdom, data=data)


def fetch_credentials():
    """
    fetches username and password from OS ENV by
    searching for FortiUser and FortiPassword
    if fails, it'll ask for input.
    """

    print("[✔] Fetching credentials")

    user = getenv("FortiUser")
    passwd = getenv("FortiPass")

    if user == None or passwd == None:
        print("[-] Could not fetch credentials from ENV")
        user = input("[👀] Username: ")
        passwd = input("[🔑] Password: ")
        passwd2 = input("[🔑] Re-Password: ")

        if passwd != passwd2:
            print("[-] Password mismatch")
            exit(1)

    return user, passwd


def ReadYamlFile(yamlfile):
    '''
    Open YAML file to get firewall info.
    returns info to the calling function.

    :param: yaml file to look into
    '''

    if isfile(yamlfile):
        with open(yamlfile, "r") as fwfile:
            firewalls = safe_load(fwfile)
        return firewalls
    else:
        print("Could not read firewalls.yml file")
        exit(1)


def get_user_input():
    """
    checks user input upon running program.
    user input can be a username or a text file,
    with usernames separated by newlines.

    """
    programname = sys.argv[0]

    if len(sys.argv) == 1:
        guide_user(programname)

    userinput = sys.argv[1].strip()
    userlist = set()

    if userinput.endswith(".txt"):
        print(f"[✔] Received {userinput} as input file")

        with open(userinput, "r") as file:
            for username in file:
                username = sanitize_username(username.strip())
                userlist.add(username)

        sorted_user_list = sorted(userlist)
        return sorted_user_list

    print(f"[✔] Received a single user: {userinput}")

    user = sanitize_username(userinput)
    userlist.add(user)
    return sorted(userlist)


def main():
    """
    gets user/user list to delete, fw credentials,
    creats FortiOSAPI object, reads firewalls.yml file
    and then checks and removes user from all firewalls.
    """

    signal.signal(signal.SIGINT, signal_handler)

    BOLD = "\033[1m"
    ENDCOLOR = "\033[0m"
    GREEN = "\033[32m"

    print(BOLD, end="")
    print(GREEN, end="")

    user, passwd = fetch_credentials()
    deletelist = get_user_input()
    firewalls = ReadYamlFile("firewalls.yml")
    device = FortiOSAPI()

    for fw in firewalls["firewalls"]:
        fwname = fw["name"]
        fwip = fw["mgmt_ip"]
        fwport = fw["port"]
        fwvdom = fw["vdom"]
        firewall = fwip + ":" + str(fwport)

        print("-" * 75)
        print(f"[✔] Logging into {fwname} using {fwip} on port {fwport}")

        device.login(host=firewall, username=user,
                     password=passwd, verify=False,
                     vdom=fwvdom)
        groups = get_all_groups(device, fwvdom)

        delete_user(device, deletelist, groups, fwname, fwvdom)

        device.logout()
        print(f"[✔] Logged out of {fwname}")
        print("-" * 75)

    print(ENDCOLOR, end="")


if __name__ == "__main__":
    main()
