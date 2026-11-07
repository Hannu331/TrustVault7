import sqlite3

database_path = "backend/data/trustvault.db"

connection = sqlite3.connect(database_path)

connection.execute(
    "UPDATE users SET role = ? WHERE role = ?",
    ("document_owner", "viewer")
)

connection.commit()

users = connection.execute(
    "SELECT username, role FROM users"
).fetchall()

print("Updated user roles:")
for user in users:
    print(user)

connection.close()