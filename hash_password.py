from werkzeug.security import generate_password_hash

# Şifreyi buraya girin
password = "123456"

# Şifreyi hash'le
hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

print("Hash'lenmiş şifre:")
print(hashed_password) 