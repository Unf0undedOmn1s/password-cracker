import hashlib

def crack_password(hash_value, password_list):
    """Crack a password hash using a dictionary attack"""
    for password in password_list:
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        if hashed_password == hash_value:
            return password
    return None

#Example usage
#Password's hash
target_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
#Common passwords as an example
common_passwords = ["password", "123456", "qwerty", "letmein", "abc123", "11111", "00000"]  

cracked_password = crack_password(target_hash, common_passwords)
if cracked_password:
    print(f"Password cracked: {cracked_password}")
else:
    print("Password not found in the list.")
