import hashlib

def encrypt_sha512(message):
    hashed_message = hashlib.sha512(message.encode()).hexdigest()
    return hashed_message

def encrypt_sha256(message):
    hashed_message = hashlib.sha256(message.encode()).hexdigest()
    return hashed_message

def menu():
    print("SHA ENCRYPTION")
    print("---------------------------")
    print("1. Encrypt input to SHA-512")
    print("2. Encrypt input to SHA-256")
    print("3. Exit")
    print("---------------------------")

    choice = input("Enter your choice (1-3): ")

    if choice == "1":
        message = input("Enter a message to encrypt: ")
        encrypted_message = encrypt_sha512(message)
        print("Encrypted message (SHA-512):", encrypted_message)
        menu()
    elif choice == "2":
        message = input("Enter a message to encrypt: ")
        encrypted_message = encrypt_sha256(message)
        print("Encrypted message (SHA-256):", encrypted_message)
        menu()
    elif choice == "3":
        print("Goodbye!")
    else:
        print("Invalid choice. Please try again.")
        menu()

menu()