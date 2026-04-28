# init_db.py
import sqlite3

connection = sqlite3.connect('database.db')

with open('schema.sql') as f:
    connection.executescript(f.read())

cur = connection.cursor()

cur.execute("INSERT INTO products (name, price, description, seller_name) VALUES ('Classic T-Shirt', 15.99, 'A comfortable, 100% cotton t-shirt.', 'admin')")
cur.execute("INSERT INTO products (name, price, description, seller_name) VALUES ('Stylish Mug', 9.99, 'A ceramic mug, perfect for your morning coffee.', 'admin')")

cur.execute("INSERT INTO users (username, password, is_admin) VALUES ('admin', 'password', 1)")

connection.commit()
connection.close()

print("Vulnerable database initialised with sample data.")
