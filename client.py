import os.path
import tkinter
from tkinter import messagebox
from tkinter.filedialog import askopenfilename
import customtkinter
import socket
from datetime import datetime
import threading
import time
import sys
import ProjectSecurity
from ProjectSecurity import symmetric_encrypt, symmetric_decrypt, hash_Password, rsa_encrypt, symmetric_encrypt_file

# Constants
HOST = '127.0.0.1'  # Local host
PORT = 54428  # Port name is last 5 digits of my ID
FORMAT = 'utf-8'
ADDR = (HOST, PORT)


def stopSocket():
    # When we stop the socket
    global logged_in, client_socket
    client_socket.send("bye".encode(FORMAT))
    time.sleep(0.1)
    logged_in = 0
    client_socket.close()
    exit(0)


def receive_text_thread(username):
    """
    Continuously listens for and handles various server messages, updating the chat interface accordingly.
    It includes functionality for room changes, user list updates, password changes, user kicking, and file transfers,
    with specific actions triggered based on the message type received.
    """
    global logged_in, chat, message_send_box, symmetric_room_key
    while logged_in == 1:
        try:
            msg_type = client_socket.recv(4).decode(FORMAT)
            time.sleep(0.3)
            if msg_type == "msgs":
                recv_msg = client_socket.recv(2048)
                recv_msg = symmetric_decrypt(recv_msg, symmetric_room_key)
                chat.configure(state="normal")  # Enable writing
                chat.insert("end", recv_msg + "\n")  # Insert new comment into chat
                chat.see("end")  # Automatically scroll down
                chat.configure(state="disabled")
            elif msg_type == "ovrf":
                messagebox.showerror("Chat Error", "You can't send more than 10 messages in a minute")
            elif msg_type == "room":
                recv_answer = client_socket.recv(5).decode(FORMAT)  # Receive answer if room changed or not
                if recv_answer == "NO_RM":
                    messagebox.showerror("Chat Error", "Such room doesn't exist, Use /rooms to pick existing one")
                elif recv_answer == "YS_RM":
                    symmetric_room_key = ""
                    symmetric_room_key = client_socket.recv(2048).decode(FORMAT)
                    symmetric_room_key = symmetric_room_key[2:-1].encode()
                    recv_line = ""
                    firstLine = 0
                    chat.configure(state="normal")  # Enable writing
                    chat.delete("0.0", "end")  # Delete the chat
                    chat.insert("0.0",
                                "*******************************************************" + "\n" +
                                "COMMANDS: /users , /changeRoom , /rooms , /changePassword , /files" + "\n" +
                                "ADMINS ALSO HAVE /kick , " + "/createRoom" + " COMMANDS" +
                                "\n" + "*******************************************************" + "\n")
                    while recv_line != "ENDLINE":
                        recv_line = client_socket.recv(1048)
                        if recv_line.decode(FORMAT) == "ENDLINE":
                            break
                        decrypt_line = symmetric_decrypt(recv_line, symmetric_room_key)
                        if firstLine == 0:
                            decrypt_line = ("###### Welcome to room " +
                                            decrypt_line + " ######")
                        chat.insert("end", decrypt_line + "\n")
                        firstLine = 1
                    chat.see("end")  # Automatically scroll down
                    chat.configure(state="disabled")
                    firstLine = 0
                    messagebox.showinfo("Success", "Welcome to the new room!")
            elif msg_type == "cpwd":  # Change password
                recv_answer = client_socket.recv(5).decode(FORMAT)  # Receive answer if password changed or not
                if recv_answer == "yes":
                    messagebox.showinfo("Success", "Password has changed! You don't have to relog")
                elif recv_answer == "no":
                    messagebox.showerror("Chat Error", "Couldn't change password, try again or relog")

            elif msg_type == "kick":  # Kick user
                recv_answer = client_socket.recv(5).decode(FORMAT)  # Receive answer kicked/not allowed/not in the room
                if recv_answer == "yes":
                    messagebox.showinfo("Success", "User was kicked to the offline lobby!")
                elif recv_answer == "no":
                    messagebox.showerror("Chat Error", "You cannot kick, you're not an admin")
                else:
                    messagebox.showinfo("Info", "No user found to kick")

            elif msg_type == "usrs":  # Show user list in the room
                recv_answer = client_socket.recv(2048).decode(FORMAT)  # Receive answer of user list
                chat.configure(state="normal")  # Enable writing
                chat.insert("end", "SYSTEM: These are the users in your room -> " + recv_answer + "\n")
                chat.configure(state="disabled")

            elif msg_type == "rlst":  # Show room list
                recv_answer = client_socket.recv(2048).decode(FORMAT)  # Receive answer of room list
                chat.configure(state="normal")  # Enable writing
                chat.insert("end", "SYSTEM: These are the rooms -> " + recv_answer + "\n")
                chat.configure(state="disabled")

            elif msg_type == "crte":  # Create a new room (Admin only)
                recv_answer = client_socket.recv(5).decode(FORMAT)  # Receive answer not Admin/created/room exists
                if recv_answer == "RDONE":
                    messagebox.showinfo("Success", "Room was created!")
                elif recv_answer == "no":
                    messagebox.showerror("Chat Error", "You cannot create a room, you're not an admin")
                else:
                    messagebox.showinfo("Info", "Room already exists!")

            elif msg_type == "file":
                chat.configure(state="normal")  # Enable writing
                chat.insert("end", "SYSTEM: Done uploading file to your room mates " + "\n")
            # Finish receiving
            elif msg_type == "rcvf":  # Disconnect
                logged_in = 0
                break
            elif msg_type == "kckd":  # You got kicked
                symmetric_room_key = ""
                messagebox.showerror("Admin", "You got kicked and put back into default room")
                chat.configure(state="normal")  # Enable writing
                chat.delete("0.0", "end")  # Delete the chat
                chat.insert("0.0",
                            "*******************************************************" + "\n" + "WELCOME TO THE CHAT"
                            + "\n" + "COMMANDS: /users , /changeRoom , /rooms , /changePassword , /files" + "\n" +
                            "ADMINS ALSO HAVE /kick , " + "/createRoom" + " COMMANDS" +
                            "\n" + "ENJOY!" + "\n" + "*******************************************************" +
                            "\n" + "\n" + "SYSTEM: You have been placed in the default offline room, "
                                          "You will be connected "
                            + "once you run: " + "/changeRoom" + "\n" + "\n")
                chat.configure(state="disabled")  # Enable writing

        except ConnectionAbortedError:
            break
        except:
            break


def submitMessage(event=None, temp_msg=None, file_path=None):
    """
    Manages message sending and specific command execution within the chat interface,
    including room management, password changes, user actions, and file uploads.
    Incorporates client-side encryption for secure communication.
    """
    global chat, symmetric_room_key, username_entry
    if temp_msg is None:
        sent_msg = str(message_send_box.get("0.0", "end-1c")).strip()
        if sent_msg == "":
            return
        elif sent_msg.startswith('/createRoom '):
            room_name = sent_msg.split('/createRoom ')[1]
            if room_name is not None:
                client_socket.send("MSSGE".encode(FORMAT))
                time.sleep(0.1)
                client_socket.send("CRTRM".encode(FORMAT))
                time.sleep(0.1)
                client_socket.send(room_name.encode(FORMAT))
                time.sleep(0.1)
                message_send_box.delete("1.0", "end")  # Delete the comment after sending
                return "break"
            else:
                message_send_box.delete("1.0", "end")  # Delete the comment after sending
                return "break"
        elif sent_msg.startswith('/changeRoom '):
            room_name = sent_msg.split('/changeRoom ')[1]
            if room_name is not None:
                client_socket.send("MSSGE".encode(FORMAT))
                time.sleep(0.1)
                client_socket.send("CHGRM".encode(FORMAT))
                time.sleep(0.1)
                client_socket.send(room_name.encode(FORMAT))
                time.sleep(0.1)
                message_send_box.delete("1.0", "end")  # Delete the comment after sending
                return "break"
            else:
                message_send_box.delete("1.0", "end")  # Delete the comment after sending
                return "break"

        elif sent_msg.startswith('/changePassword '):
            new_password = sent_msg.split('/changePassword ')[1]
            if new_password is not None:
                client_socket.send("MSSGE".encode(FORMAT))
                time.sleep(0.1)
                client_socket.send("CHGPW".encode(FORMAT))
                time.sleep(0.1)
                client_socket.send(rsa_encrypt(hash_Password(new_password), server_public_key))  # Asymmetric encryption
                time.sleep(0.3)
                message_send_box.delete("1.0", "end")  # Delete the comment after sending
                return "break"
            else:
                message_send_box.delete("1.0", "end")  # Delete the comment after sending
                return "break"

        elif sent_msg.startswith('/kick '):
            user_to_kick = sent_msg.split('/kick ')[1]
            if user_to_kick is not None:
                client_socket.send("MSSGE".encode(FORMAT))
                time.sleep(0.1)
                client_socket.send("KICKU".encode(FORMAT))
                time.sleep(0.1)
                client_socket.send(rsa_encrypt(user_to_kick, server_public_key))
                time.sleep(0.3)
                message_send_box.delete("1.0", "end")  # Delete the comment after sending
                return "break"
            else:
                message_send_box.delete("1.0", "end")  # Delete the comment after sending
                return "break"

        elif sent_msg == "/users":
            client_socket.send("MSSGE".encode(FORMAT))
            time.sleep(0.1)
            client_socket.send("USERS".encode(FORMAT))
            time.sleep(0.1)
            message_send_box.delete("1.0", "end")  # Delete the comment after sending
            return "break"

        elif sent_msg == "/rooms":
            client_socket.send("MSSGE".encode(FORMAT))
            time.sleep(0.1)
            client_socket.send("ROOMS".encode(FORMAT))
            time.sleep(0.1)
            message_send_box.delete("1.0", "end")  # Delete the comment after sending
            return "break"

        elif sent_msg == "/files":
            folder_path = os.path.join(os.getcwd(), "UsersFolder", username_entry.get().strip() + "_folder")
            os.startfile(folder_path)
            message_send_box.delete("1.0", "end")  # Delete the comment after sending
            return "break"

        else:  # Just send a message
            if symmetric_room_key == "":
                chat.configure(state="normal")  # Enable writing
                chat.insert("end", username_entry.get().strip() + ": " +
                            str(message_send_box.get("0.0", "end-1c")) + "\n")  # Insert new comment into chat
                chat.see("end")  # Automatically scroll down
                chat.configure(state="disabled")
                message_send_box.delete("1.0", "end")  # Delete the comment after sending
                return "break"
            else:
                client_socket.send("MSSGE".encode(FORMAT))
                time.sleep(0.1)
                client_socket.send("NMSSG".encode(FORMAT))
                time.sleep(0.1)
                sent_msg = username_entry.get().strip() + ": " + sent_msg
                client_socket.send(symmetric_encrypt(sent_msg, symmetric_room_key))
                time.sleep(0.1)
                message_send_box.delete("1.0", "end")  # Delete the comment after sending
                return "break"

    else:  # This is for file upload
        if symmetric_room_key == "":
            messagebox.showerror("Chat Error", "Can't upload without being in a room")
        else:
            client_socket.send("MSSGE".encode(FORMAT))
            time.sleep(0.1)
            chat.configure(state="normal")  # Enable writing
            chat.insert("end", temp_msg + "\n")  # Insert new comment into chat
            chat.see("end")  # Automatically scroll down
            chat.configure(state="disabled")
            extension = os.path.splitext(file_path)[1]
            with open(file_path, 'rb') as f:  # We read the file
                data = f.read()
            client_socket.send("ULOAD".encode(FORMAT))
            time.sleep(0.1)
            encrypted_file = symmetric_encrypt_file(data, symmetric_room_key)
            now = datetime.now()
            format_file_name = now.strftime("%Y_%m_%d_%H_%M_%S") + extension
            client_socket.send(format_file_name.encode(FORMAT))  # We send the file name
            time.sleep(0.1)
            client_socket.sendall(encrypted_file)  # Send entire file using TCP
            client_socket.send(b'<END>')  # End it with a constant end frame


def backToLogin():
    # We call the login screen
    registerFrame.forget()
    chatFrame.forget()
    LoginFrame.pack(pady=20, padx=60, fill="both", expand=True)


def disconnect():
    # Disconnect button logic
    global logged_in, chat, symmetric_room_key
    client_socket.send("DSCNT".encode(FORMAT))
    time.sleep(0.2)
    symmetric_room_key = ""
    logged_in = 0
    chat.configure(state="normal")  # Enable writing
    chat.delete("0.0", "end")  # Delete the chat
    chat.configure(state="disabled")
    chatFrame.forget()
    registerFrame.forget()
    LoginFrame.pack(pady=20, padx=60, fill="both", expand=True)


def Uploadbutton():
    # Upload file button logic
    global filePath
    filePath = askopenfilename(initialdir="/", title="Select file",
                               filetypes=(("all files", "*.*"), ("text files", "*.txt")))
    # Now upload
    if filePath != "":
        submitMessage(None, "SYSTEM: Uploading file to room members...", filePath)


def submitRegister(event=None):
    """
    Manages user registration, validating input and displaying appropriate error messages or success confirmation.
    Encrypts and sends user details for registration.
    """
    global pass_entry1, pass_entry2, username_entry1
    username = username_entry1.get().strip()
    password1 = pass_entry1.get().strip()
    password2 = pass_entry2.get().strip()
    if not username or not password1 or not password2:
        messagebox.showerror("Registration Error", "Please enter all the details.")
    elif password1 != password2:
        messagebox.showerror("Password Error", "Passwords do not match.")
    elif len(username) > 50 or len(password1) > 50 or len(password2) > 50:
        messagebox.showerror("Registration Error", "Max 50 characters for each field")
    else:
        client_socket.send("RGSTR".encode(FORMAT))
        time.sleep(0.1)
        # Send encrypted username
        client_socket.send(rsa_encrypt(username, server_public_key))
        time.sleep(0.2)
        # Send encrypted password
        password1 = hash_Password(password1)
        client_socket.send(rsa_encrypt(password1, server_public_key))  # Asymmetric encryption
        time.sleep(0.2)

        client_answer = client_socket.recv(7).decode(FORMAT)  # We get the server answer
        if client_answer == "uexists":
            messagebox.showerror("Registration Error", "Username already exists, please choose another")
        else:
            messagebox.showinfo("Success", "Registration successful!\nWelcome, Please login")
            backToLogin()  # We are back to the login screen


def chatScreen(event=None):
    """
    Handles login attempts, displaying errors for incomplete, incorrect details, or if the user is already connected.
    On successful login, it transitions to the chat interface, displaying a welcome message and instructions.
    """
    global logged_in
    global chat_thread
    global username_entry, passwd_entry, chat
    username = username_entry.get().strip()
    password = passwd_entry.get().strip()
    if not username or not password:
        messagebox.showerror("Login Error", "Please enter all the details.")
    else:
        client_socket.send("LOGIN".encode(FORMAT))
        time.sleep(0.1)
        client_socket.send(rsa_encrypt(username, server_public_key))
        time.sleep(0.4)
        # Send encrypted password
        password = hash_Password(password)
        client_socket.send(rsa_encrypt(password, server_public_key))  # Asymmetric encryption
        time.sleep(0.4)

        client_answer = client_socket.recv(1024).decode(FORMAT)  # We get the server answer
        if client_answer == "not_usr":
            messagebox.showerror("Login Error", "Username doesn't exist")
        elif client_answer == "not_pwd":
            messagebox.showerror("Login Error", "Incorrect password")
        elif client_answer == "already_on":
            messagebox.showerror("Login Error", "User already connected")
        else:
            if client_answer == "success":
                LoginFrame.forget()
                chatFrame.pack(pady=20, padx=60, fill="both", expand=True)
                # Example of chat insert
                chat.configure(state="normal")  # Enable writing
                chat.insert("0.0",
                            "*******************************************************" + "\n" + "WELCOME TO CHAT" +
                            "\n" + "COMMANDS: /users , /changeRoom , /rooms , /changePassword , /files" + "\n" +
                            "ADMINS ALSO HAVE /kick , " + "/createRoom" + " COMMANDS" +
                            "\n" + "ENJOY!" + "\n" + "*******************************************************" +
                            "\n" + "\n" + "SYSTEM: You have been placed in the default offline room, "
                                          "You will be connected " + "once you run: " + "/changeRoom" + "\n" + "\n")
                chat.configure(state="disabled")  # Enable writing
                time.sleep(0.3)
                logged_in = 1
                chat_thread = threading.Thread(target=receive_text_thread, args=(username,))
                chat_thread.start()


def createAcc():
    # We call the register frame
    LoginFrame.forget()
    registerFrame.pack(pady=20, padx=60, fill="both", expand=True)


def login_screen(frame):
    """
    Creates a login interface within the specified frame, featuring username and password entry fields,
    a login button, and an option to navigate to account creation.
    """
    global username_entry, passwd_entry
    frame.pack(pady=20, padx=60, fill="both", expand=True)

    title = customtkinter.CTkLabel(master=frame, text="Welcome Back to chat! \nLogin to Account",
                                   text_color="white",
                                   font=("Aharoni", 35))
    title.pack(pady=55, padx=100)

    username_entry = customtkinter.CTkEntry(master=frame, text_color="white", placeholder_text="Username",
                                            fg_color="black", placeholder_text_color="white",
                                            font=("", 16, "bold"), width=200, corner_radius=15, height=45)
    username_entry.pack(padx=15, pady=5)

    passwd_entry = customtkinter.CTkEntry(master=frame, text_color="white", placeholder_text="Password",
                                          fg_color="black",
                                          placeholder_text_color="white",
                                          font=("", 16, "bold"), width=200, corner_radius=15, height=45, show="*")
    passwd_entry.pack(padx=15, pady=5)

    login_btn = customtkinter.CTkButton(master=frame, text="Login", font=("", 15, "bold"), height=40, width=60,
                                        fg_color="#0085FF",
                                        cursor="hand2",
                                        corner_radius=15, command=chatScreen)
    login_btn.pack(padx=30, pady=10)

    # Binding the Enter key to the login function
    frame.bind('<Return>', chatScreen)
    username_entry.bind('<Return>', chatScreen)
    passwd_entry.bind('<Return>', chatScreen)

    create_acc_btn = customtkinter.CTkButton(master=frame, text="Create Account", font=("", 15, "bold"), height=40,
                                             width=60,
                                             fg_color="#0085FF",
                                             cursor="hand2",
                                             corner_radius=15, command=createAcc)
    create_acc_btn.pack(padx=30, pady=0)


def register_screen(frame):
    """
    Sets up the registration interface in the given frame.
    This function creates the registration form, including fields for username and password
    (with a password confirmation field), and control buttons (Submit, Back to Login) within the specified frame.
    Input validation and actions are managed through these elements.
    """
    global pass_entry1, pass_entry2, username_entry1
    title1 = customtkinter.CTkLabel(master=frame, text="Register here:",
                                    text_color="white",
                                    font=("Aharoni", 35))
    title1.pack(pady=55, padx=100)

    userLabel = customtkinter.CTkLabel(master=frame, text="Enter username:",
                                       font=("Aharoni", 17), text_color="white")
    userLabel.pack(pady=0, padx=0)

    username_entry1 = customtkinter.CTkEntry(master=frame, text_color="white", placeholder_text="Username (max 50 "
                                                                                                "chars)",
                                             fg_color="black", placeholder_text_color="white",
                                             font=("", 16, "bold"), width=230, corner_radius=15, height=45)
    username_entry1.pack(pady=5, padx=0)

    passLabel = customtkinter.CTkLabel(master=frame, text="Enter desired Password:",
                                       font=("Aharoni", 17), text_color="white")
    passLabel.pack(pady=0, padx=0)

    pass_entry1 = customtkinter.CTkEntry(master=frame, text_color="white", placeholder_text="Password (max 50 chars)",
                                         fg_color="black", placeholder_text_color="white",
                                         font=("", 16, "bold"), width=230, corner_radius=15, height=45, show="*")
    pass_entry1.pack(pady=5, padx=0)
    pass_entry2 = customtkinter.CTkEntry(master=frame, text_color="white", placeholder_text="Repeat Password",
                                         fg_color="black", placeholder_text_color="white",
                                         font=("", 16, "bold"), width=230, corner_radius=15, height=45, show="*")
    pass_entry2.pack(pady=5, padx=0)

    submit_button = customtkinter.CTkButton(master=frame, text="Submit", font=("", 15, "bold"), height=30,
                                            width=40,
                                            fg_color="#0085FF",
                                            cursor="hand2",
                                            corner_radius=15,
                                            command=submitRegister)
    submit_button.pack(pady=7, padx=5)

    # Binding the Enter key to the submit function
    frame.bind('<Return>', submitRegister)
    username_entry1.bind('<Return>', submitRegister)
    pass_entry1.bind('<Return>', submitRegister)
    pass_entry2.bind('<Return>', submitRegister)

    back_button = customtkinter.CTkButton(master=frame, text="Back to login", font=("", 15, "bold"), height=30,
                                          width=40,
                                          fg_color="#0085FF",
                                          cursor="hand2",
                                          corner_radius=15, command=backToLogin)
    back_button.pack(pady=7, padx=5)


def chat_screen(frame):
    """
        Sets up the chat interface in the given frame.
        This function creates a chat display area, a message input box, and control buttons (Upload File, Send, Disconnect)
        within the specified frame. The chat display is read-only, and input is through the message box. Actions are
        controlled by the buttons, each tied to its respective function.
    """
    global username_entry, passwd_entry, filePath, chat, message_send_box

    title = customtkinter.CTkLabel(master=frame, text="Chat",
                                   text_color="white",
                                   font=("Aharoni", 35))
    title.pack(pady=10, padx=100)

    chat = customtkinter.CTkTextbox(master=frame, width=550, height=350, corner_radius=5,
                                    fg_color="lightgray", wrap='word', text_color="black", font=('Sans-serif', 16))
    chat.pack()
    chat.configure(state="disabled")  # Configure chat to be read-only

    message_send_box = customtkinter.CTkTextbox(master=frame, width=500, height=50, corner_radius=5,
                                                fg_color="gray", wrap='word', text_color="black",
                                                font=('Sans-serif', 12))

    message_send_box.pack(pady=10)

    buttons_frame = customtkinter.CTkFrame(master=frame, bg_color="#212121")
    buttons_frame.pack()  # Adjust padding as needed

    upload_btn = customtkinter.CTkButton(master=buttons_frame, text="Upload File", font=("", 15, "bold"),
                                         height=40,
                                         width=60, cursor="hand2", corner_radius=15, command=Uploadbutton)

    upload_btn.pack(side="left", padx=10)  # Adjust 'side' and 'padx' as needed

    send_btn = customtkinter.CTkButton(master=buttons_frame, text="Send", font=("", 15, "bold"), height=40, width=60,
                                       cursor="hand2", corner_radius=15, command=submitMessage)
    send_btn.pack(side="left", padx=10)  # Adjust 'side' and 'padx' as needed

    disconnect_btn = customtkinter.CTkButton(master=buttons_frame, text="Disconnect", font=("", 15, "bold"),
                                             height=40,
                                             width=60, cursor="hand2", corner_radius=15,
                                             command=disconnect)
    disconnect_btn.pack(side="left", padx=10)  # Adjust 'side' and 'padx' as needed

    # Binding the Enter key to the submit function
    frame.bind('<Return>', submitMessage)
    message_send_box.bind('<Return>', submitMessage)


# We use 'customtkinter' and 'tkinter' libraries to make a GUI
# Each frame = a different screen
customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")
root = customtkinter.CTk()
root.geometry("700x550")
root.resizable(False, False)
root.title("Networking chat")

# We create a few globals to use them around the entire program
global pass_entry1, pass_entry2, username_entry, username_entry1, \
    passwd_entry, filePath, msg, room, chat, message_send_box, logged_in, chat_thread, symmetric_room_key
symmetric_room_key = ""

# Login frame/screen
LoginFrame = customtkinter.CTkFrame(master=root)
login_screen(LoginFrame)  # We add the screen attributes

# Register frame/screen
registerFrame = customtkinter.CTkFrame(master=root)
register_screen(registerFrame)  # We add the screen attributes

# Chat frame/screen
chatFrame = customtkinter.CTkFrame(master=root)
chat_screen(chatFrame)  # We add the screen attributes

# Server side socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    client_socket.connect((HOST, PORT))
except:
    messagebox.showerror("Error", "Server is down, please try again when it is up")
    sys.exit()

# ------------------------------------------------------------------------------------------------------------
# Security logic and key exchange
private_key, public_key = ProjectSecurity.generate_rsa_keys()  # We generate our own public/private keys

# Serialize the key to make it in bits
serialized_public_key = ProjectSecurity.serialize_public_key(public_key)
client_socket.send(serialized_public_key)

# Receiving public key from the server
pem_data = client_socket.recv(4096)  # Adjust buffer size as needed
server_public_key = ProjectSecurity.load_public_key(pem_data)

# We stop GUI socket for when we close the window
root.protocol("WM_DELETE_WINDOW", stopSocket)
root.mainloop()
