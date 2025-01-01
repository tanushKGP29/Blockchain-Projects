import hashlib
import os
import base64

def generate_salt():
    return base64.b64encode(os.urandom(16)).decode('utf-8')

def hash_password(password, salt):
    password_salt_combo = password + salt
    hash_object = hashlib.sha256(password_salt_combo.encode('utf-8'))
    return hash_object.hexdigest()

user_data = {}

def sign_up():
    username = input("Enter username: ")
    password = input("Enter password: ")
    
    salt = generate_salt()
    hashed_password = hash_password(password, salt)
    

    user_data[username] = {
        'hashed_password': hashed_password,
        'salt': salt
    }
    
    print("Sign up successful!")

def login():
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    
    
    if username in user_data:
        stored_salt = user_data[username]['salt']
        stored_hashed_password = user_data[username]['hashed_password']
        
        hashed_password = hash_password(password, stored_salt)
        
        if hashed_password == stored_hashed_password:
            print("You are logged in!")
        else:
            print("Login error: Incorrect password.")
    else:
        print("Login error: Username not found.")

def main():
    while True:
        choice = input("Select an option (sign up / login / exit): ").strip().lower()
        if choice == 'sign up':
            sign_up()
        elif choice == 'login':
            login()
        elif choice == 'exit':
            print("Exiting the program.")
            break
        else:
            print("Invalid option. Please choose 'sign up', 'login', or 'exit'.")

if __name__ == "__main__":
    main()