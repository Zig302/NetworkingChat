import socket
import threading
import time
import csv
from datetime import datetime, timedelta
import os
import ProjectSecurity
from ProjectSecurity import (symmetric_encrypt, symmetric_decrypt, rsa_decrypt,
                             symmetric_decrypt_file, generate_symmetric_key)

# Constants
HOST = '127.0.0.1'  # Local host
PORT = 54428  # Random chosen port number
FORMAT = 'utf-8'  # Define the encoding format of messages from client-server
ADDR = (HOST, PORT)  # Creating a tuple of IP+PORT

# *** Data we want to keep ***
# List of lists, each sub list is with form ('address', 'username', 'room', 'public_key', 'client')
online_clients = []
rooms = []


def change_Password(address, newPassword):
    """
    Change password function
    """
    username = find_username(address)
    updated = False
    users = []

    with open("ChatsDB/users.csv", mode='r') as csvfile:
        csvreader = csv.DictReader(csvfile)
        users = list(csvreader)  # Convert to list to reuse

    with open("ChatsDB/users.csv", mode='w', newline='') as csvfile:
        fieldnames = ['Username', 'Password', 'IsAdmin']
        csvwriter = csv.DictWriter(csvfile, fieldnames=fieldnames)
        csvwriter.writeheader()
        for user in users:
            if user['Username'] == username:
                user['Password'] = newPassword
                updated = True
            csvwriter.writerow(user)

    return "yes" if updated else "no"


def bring_room_Key(room):
    """
    Retrieve room asymmetric key
    """
    with open("ChatsDB/rooms.csv", mode='r') as csvfile:
        csvreader = csv.DictReader(csvfile, delimiter=',')
        for row in csvreader:
            if row['room'] == room:
                return row['key']


def user_list(room):
    """
    Retrieve user list in a room
    """
    ans = ""
    for row in online_clients:
        if row[2] == room:
            ans += row[1]
            ans += ", "
    return ans[:-2]


def room_list():
    """
    Retrieve the rooms list
    """
    ans = ""
    with open("ChatsDB/rooms.csv", mode='r') as csvfile:
        csvreader = csv.DictReader(csvfile, delimiter=',')
        for row in csvreader:
            ans += row['room']
            ans += ", "
    return ans[:-2]


def disconnect_user(address):
    """
    Disconnect a user
    """
    for row in online_clients:
        if row[0] == address:
            online_clients.remove(row)
            print('[CLIENT DISCONNECTED] in address: ', address)


def create_txt_file(file_name):
    """
    Create a text file
    """
    with open(file_name, 'w') as f:
        pass  # File is created.


def append_to_txt_file(file_name, text_to_append):
    """
    Append into a text file
    """
    with open(file_name, 'a') as f:
        f.write(text_to_append + '\n')  # Adds the text on a new line.


def find_online_username(user):
    """
    Find an online username
    """
    for row in online_clients:
        if row[1] == user:
            return row[1]
    return ""


def find_username(address):
    """
    Find username of a client address
    """
    for row in online_clients:
        if row[0] == address:
            return row[1]
    return ""


def find_client(username):
    """
    Find the client according to a username
    """
    for row in online_clients:
        if row[1] == username:
            return row[0]
    return ""


def find_userRoom(address):
    """
    Retrieve user's Room with his address
    """
    for row in online_clients:
        if row[0] == address:
            return row[2]
    return ""


def is_Admin(address):
    """
    Check if someone is an admin
    """
    user = find_username(address)
    with open("ChatsDB/users.csv", mode='r') as csvfile:
        csvreader = csv.DictReader(csvfile, delimiter=',')
        for row in csvreader:
            if row['IsAdmin'] == "1" and row['Username'] == user:
                return "yes"
        return "no"


def kick_Client(username):
    """
    Kick a user out of the rooms
    """
    for userClient in online_clients:
        if userClient[1] == username:
            kicked_Client = userClient[4]
            kicked_Client.send("kckd".encode(FORMAT))


def broadcast(message, room):
    """
    Broadcast a message to all clients in a certain room
    """
    dir_path = "ChatsDB/room_logs"
    file_path = os.path.join(dir_path, f"{room}.txt")
    roomKey = bring_room_Key(room)
    with open(file_path, 'a') as file:
        file.write(str(message) + "\n")

    client_list = []
    for client in online_clients:  # Collect all clients in the room
        if client[2] == room:
            client_list.append(client[4])

    for client_id in client_list:
        client_id.send("msgs".encode(FORMAT))
        time.sleep(0.1)
        client_id.send(message)


def username_exists(username_to_check):
    """
    Check if a certain username exists already
    """
    with open("ChatsDB/users.csv", mode='r') as csvfile:
        csvreader = csv.DictReader(csvfile, delimiter=',')
        for row in csvreader:
            if row['Username'] == username_to_check:
                return "yes"
        return "no"


def room_exists(room_to_check):
    """
    Check if a certain room exists already
    """
    with open("ChatsDB/rooms.csv", mode='r') as csvfile:
        csvreader = csv.DictReader(csvfile, delimiter=',')
        for row in csvreader:
            if row['room'] == room_to_check:
                return "yes"
        return "no"


def password_correct(username_to_check, password_to_check):
    """
        Check if a logged-in username and password are correct
    """
    with open("ChatsDB/users.csv", mode='r') as csvfile:
        csvreader = csv.DictReader(csvfile, delimiter=',')
        for row in csvreader:
            if row['Username'] == username_to_check:
                if row['Password'] == password_to_check:
                    return "yes"
        return "no"


def add_user(username, password):
    """
        Finish registering a user
    """
    file_path = "ChatsDB/users.csv"  # Path to my CSV file

    with open(file_path, mode='a', newline='', encoding='utf-8') as file:
        csv_writer = csv.writer(file)
        # The CSV structure is username,password
        csv_writer.writerow([username, password, 0])


def create_Room(room_name):
    """
        New room creation
    """
    file_path = "ChatsDB/rooms.csv"  # Path to my CSV files
    dir_path = "ChatsDB/room_logs"
    roomKey = generate_symmetric_key()
    with open(file_path, mode='a', newline='', encoding='utf-8') as file:
        csv_writer = csv.writer(file)
        # The CSV structure is username,password
        csv_writer.writerow([room_name, roomKey])
    os.makedirs(dir_path, exist_ok=True)
    file_path = os.path.join(dir_path, f"{room_name}.txt")
    with open(file_path, 'w') as file:
        pass  # The file is created and then closed.
    with open(file_path, 'a') as file:
        enc_room = symmetric_encrypt(room_name, roomKey)
        file.write(str(enc_room) + "\n")


def create_user_folder(username):
    """
        New folder for a user creation
    """
    # Define the path for the new folder within UsersFolder
    new_folder_path = os.path.join("UsersFolder", f"{username}_folder")

    # Create the folder if it does not exist
    if not os.path.exists(new_folder_path):
        os.makedirs(new_folder_path)
        print(f"Folder created at {new_folder_path}")
    else:
        print("Folder already exists.")


def copy_files(file, room, fileName):
    """
        Copy received files to users in a specific room
    """
    for user in online_clients:
        if user[2] == room:
            path = "UsersFolder/" + user[1] + "_folder/" + fileName
            with open(path, 'wb') as f:
                f.write(file)


def send_Room_History(client, room, roomKey):
    """
        Send room history
    """
    dir_path = "ChatsDB/room_logs"
    file_path = os.path.join(dir_path, f"{room}.txt")
    file_size = os.path.getsize(file_path)
    with open(file_path, 'r') as file:
        for line in file:
            byte_line = line.strip()[2:-1].encode(FORMAT)
            client.send(byte_line)
            time.sleep(0.05)
    client.send("ENDLINE".encode(FORMAT))


def handler(client, address):
    """
    Handles client actions on the server side, including user registration, login, messaging,
    room management, file upload, and user disconnection.
    Implements security through encryption and decryption of user data.
    Implements rate limiting on the server side, only 10 messages per minute for each client
    """
    print('[CLIENT CONNECTED] on address: ', str(address))

    # Receiving public key from the client
    pem_data = client.recv(4096)  # Adjust buffer size as needed
    client_public_key = ProjectSecurity.load_public_key(pem_data)

    # Sending server's public key to the client
    serialized_public_key = ProjectSecurity.serialize_public_key(public_key)
    client.send(serialized_public_key)

    msgsCounter = 0
    while True:
        try:
            action = client.recv(5).decode(FORMAT)  # We got the action we want the server to do
            if action == "":  # Client closed connection successfully
                client.close()
                print('[CLIENT DISCONNECTED] on address: ', str(address))
                break
            # print("Client wants to do: " + action)  # For QA we print the action
            # size = client.recv(1024)  # We get the size of the operation message
            if action == "RGSTR":  # Register
                recv_username = client.recv(2048)  # We receive the username
                # Decrypt username
                recv_username = rsa_decrypt(recv_username, private_key)

                recv_password = client.recv(2048)  # We receive the password HASHED
                # Decrypt password
                recv_password = rsa_decrypt(recv_password, private_key)
                if username_exists(recv_username) == "yes":
                    client.send("uexists".encode(FORMAT))
                else:
                    add_user(recv_username, recv_password)
                    create_user_folder(recv_username)
                    print('[CLIENT REGISTERED] on username: ', recv_username)
                    client.send("success".encode(FORMAT))

            elif action == "LOGIN":  # Login
                recv_username = client.recv(2048)  # We receive the username
                # Decrypt username
                recv_username = rsa_decrypt(recv_username, private_key)

                recv_password = client.recv(2048)  # We receive the password
                # Decrypt password
                recv_password = rsa_decrypt(recv_password, private_key)
                online_User = find_online_username(recv_username)
                if online_User == "":
                    if username_exists(recv_username) != "yes":
                        client.send("not_usr".encode(FORMAT))
                    elif password_correct(recv_username, recv_password) != "yes":
                        client.send("not_pwd".encode(FORMAT))
                    else:
                        print('[CLIENT LOGGED] on username: ', recv_username)
                        online_clients.append([address, recv_username, '', client_public_key, client])
                        client.send("success".encode(FORMAT))
                else:
                    client.send("already_on".encode(FORMAT))

            elif action == "MSSGE":  # Send a message
                sub_action = client.recv(5).decode(FORMAT)  # We got the sub action we want the server to do
                # receive sub_action
                if sub_action == "CHGRM":  # Change room
                    recv_room = client.recv(1024).decode(FORMAT)
                    client.send("room".encode(FORMAT))
                    if room_exists(recv_room) == "yes":
                        for client_info in online_clients:
                            if client_info[0] == address:
                                client_info[2] = recv_room
                                client.send("YS_RM".encode(FORMAT))
                                room_key = bring_room_Key(recv_room)
                                time.sleep(0.2)
                                client.send(room_key.encode(FORMAT))
                                time.sleep(0.2)
                                send_Room_History(client, recv_room, room_key)  # Sending room history of chat
                    else:
                        client.send("NO_RM".encode(FORMAT))

                elif sub_action == "USERS":  # Show users in room
                    client.send("usrs".encode(FORMAT))
                    room = find_userRoom(address)
                    users_list = user_list(room)
                    client.send(users_list.encode(FORMAT))

                elif sub_action == "ROOMS":  # Show rooms to client
                    client.send("rlst".encode(FORMAT))
                    roomList = room_list()
                    client.send(roomList.encode(FORMAT))

                elif sub_action == "CHGPW":  # Change password
                    recv_new_password = client.recv(2048)  # We receive the new password
                    recv_new_password = rsa_decrypt(recv_new_password, private_key)  # Decrypt password
                    client.send("cpwd".encode(FORMAT))
                    pw_answer = change_Password(address, recv_new_password)
                    client.send(pw_answer.encode(FORMAT))
                    print('[CLIENT CHANGED PASSWORD] on address: ', address)
                elif sub_action == "KICKU":  # Kick user (for admin)
                    recv_user_to_kick = client.recv(2048)  # We receive user to kick
                    recv_user_to_kick = rsa_decrypt(recv_user_to_kick, private_key)  # Decrypt user
                    client.send("kick".encode(FORMAT))
                    isAdmin = is_Admin(address)
                    if isAdmin == "yes":
                        foundOnline = find_client(recv_user_to_kick)
                        foundUsr = find_username(foundOnline)
                        if foundUsr != "":
                            for client_info in online_clients:
                                if client_info[0] == foundOnline:
                                    client_info[2] = ""
                                    client.send("yes".encode(FORMAT))
                                    time.sleep(0.1)
                                    kick_Client(recv_user_to_kick)
                                    print('[CLIENT KICKED] on username: ', client_info[1])
                        else:
                            client.send("noUsr".encode(FORMAT))
                    elif isAdmin == "no":
                        client.send("no".encode(FORMAT))
                        time.sleep(0.2)

                elif sub_action == "CRTRM":  # Create room (for admin)
                    recv_room = client.recv(1024).decode(FORMAT)
                    client.send("crte".encode(FORMAT))
                    isAdmin = is_Admin(address)
                    if isAdmin == "yes":
                        if room_exists(recv_room) == "no":
                            create_Room(recv_room)
                            client.send("RDONE".encode(FORMAT))
                            print('[ADMIN CREATED A ROOM]: ', recv_room)
                        else:
                            client.send("EXIST".encode(FORMAT))
                    elif isAdmin == "no":
                        client.send("no".encode(FORMAT))
                        time.sleep(0.2)
                elif sub_action == "ULOAD":  # Upload a file
                    recv_file_name = client.recv(1024).decode(FORMAT)  # We get file name
                    time.sleep(0.1)
                    dir_path = "ChatsDB/receivedFiles"
                    file_path = os.path.join(dir_path, recv_file_name)
                    file = open(file_path, 'wb')
                    file_bytes = b''
                    while True:
                        bytes_read = client.recv(1024)
                        if bytes_read[-5:] == b'<END>':
                            file_bytes += bytes_read[:-5]
                            break
                        else:
                            file_bytes += bytes_read
                    user_room = find_userRoom(address)
                    roomKey = bring_room_Key(user_room)[2:-1]
                    file.write(file_bytes)
                    file.close()
                    decrypt_file = symmetric_decrypt_file(file_bytes, roomKey)
                    client.send("file".encode(FORMAT))
                    copy_files(decrypt_file, user_room, recv_file_name)
                    print('[FILE UPLOADED] in room: ', user_room)
                elif sub_action == "NMSSG":  # Just a normal message
                    recv_msg = client.recv(2048)
                    # We keep the datetime of the first sent msg
                    if msgsCounter == 0:
                        timeStamp = datetime.now()
                    if datetime.now() - timeStamp > timedelta(minutes=1):
                        timeStamp = datetime.now()
                        msgsCounter = 0
                    if (datetime.now() - timeStamp < timedelta(minutes=1)) and (msgsCounter > 10):
                        client.send("ovrf".encode(FORMAT))
                    else:
                        transmit_Room = find_userRoom(address)
                        broadcast(recv_msg, transmit_Room)
                        msgsCounter += 1

                else:
                    pass
            elif action == "DSCNT":  # Disconnect
                client.send("rcvf".encode(FORMAT))
                disconnect_user(address)

            elif action == "bye":  # Close connection
                disconnect_user(address)
                time.sleep(0.1)

        except:
            client.close()
            break


def receive():
    """
    Listens for incoming connections on the server and, for each connection
    it initiates a new thread to handle the client
    """
    while True:
        client, address = server.accept()
        # Now start a new thread for each connection
        thread = threading.Thread(target=handler, args=(client, address))
        thread.start()


# Initiate server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)
server.listen()
print(f"[LISTENING] server is listening on {HOST}")

# Security stuff
# We generate our own public/private keys for when a new room is created
private_key, public_key = ProjectSecurity.generate_rsa_keys()
client_file_key = b'7gBEGVmPCD5RKUlCRcTLjcXVRNdO5TIRuVL_Yg_ERbg='

receive()  # Now we are listening
