"""
This class is used to make secret keys and to decrypt messages.
The class gets an input of a message and a key and returns the decrypted message.
the decryption goes through the following steps:
1. The message is split into a list of characters
2. The characters are converted to numbers
3. The numbers are added to the key
4. The numbers are converted back to characters
5. The characters are joined to a string
"""
import random
from socket import *
import select
import pickle

def start_server():
    """
    Using select
    :return:
    """

    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.bind(('localhost', 8383))
    server_socket.listen(5)
    server_socket.setblocking(False)
    inputs = [server_socket]
    while True:
        readable, writable, exceptional = select.select(inputs, [], [])
        for s in readable:
            if s is server_socket:
                client_socket, client_address = server_socket.accept()
                client_socket.setblocking(False)
                inputs.append(client_socket)
            else:
                data = s.recv(1024)
                if data:
                    print(data.decode())
                    if data.decode() == "encrypt":
                        k = random.randint(1, 100)
                        encrypted_message = encrypt("Top_Secret_Admin", k)
                        print(encrypted_message)
                        s.send(pickle.dumps((k, encrypted_message)))
                    elif "decrypt" in data.decode():
                        decrypted_message = decrypt(extract_key(data.decode()))
                        s.send(decrypted_message.encode())
                else:
                    inputs.remove(s)
                    s.close()


def extract_key(message):
    """
    The function extracts the key from the message
    """
    key = 0
    mul = 1
    for char in message[::-1]:
        if char.isdigit():
            key += int(char) * mul
            mul *= 10
    return key


def encrypt(message, key):
    """
    The function encrypts a message with a key
    """
    encrypted_message = []
    for char in message:
        char = ord(char)
        char = char + key
        char = chr(char)
        encrypted_message.append(char)

    for i in range(len(encrypted_message)):
        encrypted_message[i] = chr((ord(encrypted_message[i])) * key)

    encrypted_message = "".join(encrypted_message)

    # save the encrypted message to a file /Keys/admin_key.txt
    with open("admin_key.key", "w", encoding="utf-8") as f:
        f.write(encrypted_message)


    return encrypted_message


def decrypt(key):
    """
    The function decrypts a message with a key
    """
    # open key
    with open("admin_key.key", "r", encoding="utf-8") as f:
        message = f.read()

    decrypted_message = []
    for char in message:
        char = ord(char)
        char = int(char / key)
        char = chr(char - key)
        decrypted_message.append(char)

    decrypted_message = "".join(decrypted_message)
    return decrypted_message


if __name__ == "__main__":
    start_server()