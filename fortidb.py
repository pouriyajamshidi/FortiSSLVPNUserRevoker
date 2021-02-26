import sqlite3
from contextlib import closing
from datetime import datetime


class DB:
    '''Database Commands'''

    create_users_table = '''
                    CREATE TABLE IF NOT EXISTS RevokedVPNUsers 
                    (
                     id INTEGER PRIMARY KEY,
                     Username TEXT NOT NULL,
                     Site TEXT NOT NULL,
                     Status TEXT NOT NULL, 
                     Date TEXT NOT NULL
                    )
                    '''

    create_groups_table = '''
                    CREATE TABLE IF NOT EXISTS UsersGroup 
                    (
                     id INTEGER PRIMARY KEY,
                     UserID INTEGER NOT NULL,
                     Groups TEXT,
                     FOREIGN KEY (UserID) REFERENCES RevokedVPNUsers (id)
                    )
                    '''

    insert_user = '''
                    INSERT INTO RevokedVPNUsers 
                    (
                     Username, Site, Status, Date
                    ) VALUES (?, ?, ?, ?)
                    '''

    insert_group = '''
                    INSERT INTO UsersGroup (UserID, Groups) VALUES 
                    (?, ?)
                    '''

    update_userstatus = '''
                    UPDATE RevokedVPNUsers SET Status = (?) WHERE Username = (?) AND Site = (?)
                    '''

    display_all_users = '''
                        SELECT id, Username, Site, Status,
                         Date FROM RevokedVPNUsers
                        '''

    fetch_status = '''
                        SELECT Status FROM RevokedVPNUsers
                        '''

    all_groups_query = '''
                       SELECT UserID, Groups FROM UsersGroup
                       '''

    username_query = '''
                     SELECT id FROM RevokedVPNUsers
                     WHERE Username = (?)
                     '''

    group_query = '''
                     SELECT id, groups FROM UsersGroup
                     WHERE UserID = (?)
                     '''

    site_query = '''
                     SELECT Site FROM RevokedVPNUsers
                     WHERE id = (?)
                     '''


def get_date():
    date_time = datetime.now()
    date_time = date_time.strftime("%Y-%b-%d %H:%M")
    return str(date_time)


def sanitize_groups(groups):
    '''If groups is a list, convert to string'''

    if len(groups) == 1:
        return groups[0]
    elif len(groups) > 1:
        return ", ".join(groups)


def operate_on_DB(dbname, username, site, status, group):

    date = get_date()
    group = sanitize_groups(group)

    with closing(sqlite3.connect(dbname)) as DBconnection:
        with closing(DBconnection.cursor()) as cursor:
            cursor.execute(DB.create_users_table)
            cursor.execute(DB.create_groups_table)
            cursor.execute(DB.insert_user, (username, site,
                                            status, date))

            UserID = cursor.lastrowid
            cursor.execute(DB.insert_group, (UserID, group))

            DBconnection.commit()

    print(f"[✔] updated {username}'s database status in {site} to \"{status}\"")

            # total_DB_changes = DBconnection.total_changes

    # print(f"[*] Total number of changes made to Database: {total_DB_changes}")


def update_userstatus(dbname, status, username, site):

    if not isinstance(username, str):
        for user in username:
            with closing(sqlite3.connect(dbname)) as DBconnection:
                with closing(DBconnection.cursor()) as cursor:
                    cursor.execute(DB.update_userstatus,
                                   (status, user, site))
                    DBconnection.commit()

            print(f"[✔] updated {user}'s database status in {site} to \"{status}\"")
    else:
        with closing(sqlite3.connect(dbname)) as DBconnection:
            with closing(DBconnection.cursor()) as cursor:
                cursor.execute(DB.update_userstatus,
                               (status, username, site))
                DBconnection.commit()

        print(f"[✔] updated {username}'s database status in {site} to \"{status}\"")


def fetch_status(dbname):

    with closing(sqlite3.connect(dbname)) as DBconnection:
        with closing(DBconnection.cursor()) as cursor:
            status = cursor.execute(DB.fetch_status).fetchall()
            return status[0][0]


def display_revoked_users(dbname):

    with closing(sqlite3.connect(dbname)) as DBconnection:
        with closing(DBconnection.cursor()) as cursor:
            user_rows = cursor.execute(DB.display_all_users).fetchall()

    formatted_result = [f"{cnt:<5}{username:<30}{site:<20}{status:<20}{date:<15}"
                        for cnt, username, site, status, date in user_rows]

    Count, username, site, status, date = "ID", "Username", "Site", "Status", "Date"

    print("\n".join(
        [f"{Count:<5}{username:<30}{site:<20}{status:<20}{date:<15}"] + formatted_result))


def display_user_groups(dbname):

    answer = input(
        "\n[*] Would you like to see groups associated with a user (y/n)? ")

    if answer.lower() != "y":
        exit()

    user = input("[*] Enter username: ").title()

    with closing(sqlite3.connect(dbname)) as DBconnection:
        with closing(DBconnection.cursor()) as cursor:
            username_rows = cursor.execute(
                DB.username_query, (user,)).fetchall()

            if not username_rows:
                print("[❌] User not found")
                exit()

            for usrIDs in username_rows:
                for usrID in usrIDs:
                    group_query = cursor.execute(
                        DB.group_query, (usrID,)).fetchall()
                    site = cursor.execute(DB.site_query, (usrID,)).fetchall()
                    print(
                        f"[✔] {user} in {site[0][0]} was a member of:\n\t{group_query[0][1]}")


if __name__ == "__main__":

    BOLD = "\033[1m"
    ENDCOLOR = "\033[0m"
    CYAN = "\033[1;36m"
    
    print(BOLD, end="")
    print(CYAN, end="")

    DB_Name = "RevokedUsers.db"
    display_revoked_users(DB_Name)
    display_user_groups(DB_Name)

    print(ENDCOLOR, end="")
