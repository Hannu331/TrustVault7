import hashlib,secrets

def hash_password(password):
    salt=secrets.token_hex(16); digest=hashlib.pbkdf2_hmac('sha256',password.encode(),salt.encode(),100000).hex(); return salt+'$'+digest

def verify_password(password,stored):
    try:
        salt,expected=stored.split('$',1); actual=hashlib.pbkdf2_hmac('sha256',password.encode(),salt.encode(),100000).hex(); return secrets.compare_digest(actual,expected)
    except ValueError: return False
