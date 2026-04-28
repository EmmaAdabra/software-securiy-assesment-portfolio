# app.py
import sqlite3
from flask import Flask, request, redirect, url_for, make_response, flash

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

app = Flask(__name__)
app.secret_key = 'a-very-secret-and-unique-key'

@app.route('/')
def home():
    logged_in_user = request.cookies.get('username')
    current_user = None

    conn = get_db_connection()
    
    if logged_in_user:
        query = f"SELECT * FROM users WHERE username = '{logged_in_user}'"
        current_user = conn.execute(query).fetchone()

    products = conn.execute('SELECT * FROM products').fetchall()
    conn.close()

    html = f"""
    <!DOCTYPE html>
    <html><head>
        <title>My Shop</title>
        <link rel="stylesheet" href="{ url_for('static', filename='css/style.css') }">
    </head>
    <body>
        <h1>Welcome to My Shop{', ' + current_user['username'] if current_user else ''}!</h1>
        
        <nav>
            <a href="{ url_for('home') }">Home</a> | 
            <a href="{ url_for('about') }">About</a>
    """
    
    if current_user:
        html += f" | <a href='{url_for('logout')}'>Logout</a>"
        
        if current_user['is_admin']:
            html += f" | <a href='{url_for('admin_panel')}'>Admin Panel</a>"
        
        if current_user['is_seller'] or current_user['is_admin']:
            html += f" | <a href='{url_for('add_product')}'>Add a Product</a>"
        elif not current_user['is_seller'] and not current_user['is_admin']:
            html += f" | <a href='{url_for('become_seller')}'>Become a Seller</a>"
    else:
        html += f"""
             | <a href="{ url_for('login') }">Login</a>
             | <a href="{ url_for('register') }">Register</a>
        """

    html += "</nav><hr><h2>Products</h2>"

    for product in products:
        html += f"""
        <div>
            <h2><a href="{url_for('product_page', product_id=product['id'])}">{product['name']}</a></h2>
            <p><strong>Price:</strong> £{product['price']} | <strong>Seller:</strong> {product['seller_name']}</p>
            <p>{product['description']}</p>
        </div>
        <hr>
        """
    
    html += "</body></html>"
    return html

@app.route('/about')
def about():
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>About Us</title>
        <link rel="stylesheet" href="{ url_for('static', filename='css/style.css') }">
    </head>
    <body>
        <h1>About Our Shop</h1>
        <p>This is the page where we talk about ourselves.</p>
        <a href="/">Go back home</a>
    </body>
    </html>
    """
    return html

@app.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        try:
            query = f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')"
            conn.execute(query)
            conn.commit()
        except conn.IntegrityError:
            flash("Username already exists. Please choose another.")
            conn.close()
            return redirect(url_for('register'))
        
        conn.close()
        flash("Registration successful! Please log in.")
        return redirect(url_for('login'))

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Register</title>
        <link rel="stylesheet" href="{ url_for('static', filename='css/style.css') }">
    </head>
    <body>
        <h1>Register for an Account</h1>
        <form method="post">
            <label for="username">Username</label>
            <input type="text" name="username" id="username" required>
            <br>
            <label for="password">Password</label>
            <input type="password" name="password" id="password" required>
            <br>
            <button type="submit">Register</button>
        </form>
    </body>
    </html>
    """
    return html

@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        user = conn.execute(query).fetchone()
        conn.close()

        if user:
            resp = make_response(redirect(url_for('home')))
            resp.set_cookie('username', user['username'])
            return resp
        else:
            flash('Incorrect username or password.')
            return redirect(url_for('login'))

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login</title>
        <link rel="stylesheet" href="{ url_for('static', filename='css/style.css') }">
    </head>
    <body>
        <h1>Login</h1>
        <form method="post">
            <label for="username">Username</label>
            <input type="text" name="username" id="username" required>
            <br>
            <label for="password">Password</label>
            <input type="password" name="password" id="password" required>
            <br>
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    """
    return html

@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('login')))
    resp.delete_cookie('username')
    flash('You have been logged out.')
    return resp

@app.route('/become_seller', methods=('GET', 'POST'))
def become_seller():
    logged_in_user = request.cookies.get('username')
    if not logged_in_user:
        flash("You must be logged in to do this.")
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    if request.method == 'POST':
        query = f"UPDATE users SET is_seller = 1 WHERE username = '{logged_in_user}'"
        conn.execute(query)
        conn.commit()
        conn.close()
        flash("Congratulations, you are now a seller!")
        return redirect(url_for('home'))

    html = f"""
    <!DOCTYPE html><html><body>
        <h1>Become a Seller</h1>
        <p>Click the button below to upgrade your account to a seller account.</p>
        <form method="post">
            <button type="submit">Become a Seller</button>
        </form>
        <br>
        <a href="{url_for('home')}">Go back</a>
    </body></html>
    """
    conn.close()
    return html

@app.route('/add', methods=('GET', 'POST'))
def add_product():
    logged_in_user = request.cookies.get('username')
    if not logged_in_user:
        flash("You need to be logged in.")
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute(f"SELECT * FROM users WHERE username = '{logged_in_user}'").fetchone()
    
    if not (user['is_seller'] or user['is_admin']):
        flash("You must be a seller or admin to add products.")
        conn.close()
        return redirect(url_for('home'))

    if request.method == 'POST':
        name = request.form['name']
        price = request.form['price']
        description = request.form['description']

        query = f"INSERT INTO products (name, price, description, seller_name) VALUES ('{name}', '{price}', '{description}', '{logged_in_user}')"
        conn.execute(query)
        conn.commit()
        conn.close()
        
        flash("Product listed successfully!")
        return redirect(url_for('home'))

    conn.close()
    html = """
    <!DOCTYPE html><html><body>
    <h1>List a New Product</h1>
    <form method="post">
        <label for="name">Product Name</label>
        <input type="text" name="name" id="name" required>
        <br>
        <label for="price">Price</label>
        <input type="number" step="0.01" name="price" id="price" required>
        <br>
        <label for="description">Description</label>
        <textarea name="description" id="description" required></textarea>
        <br>
        <button type="submit">List Product</button>
    </form>
    <br><a href="/">Cancel</a>
    </body></html>
    """
    return html

@app.route('/edit/<int:product_id>', methods=('GET', 'POST'))
def edit_product(product_id):
    logged_in_user = request.cookies.get('username')
    if not logged_in_user:
        flash("You need to be logged in.")
        return redirect(url_for('login'))

    conn = get_db_connection()
    user_query = f"SELECT * FROM users WHERE username = '{logged_in_user}'"
    user = conn.execute(user_query).fetchone()
    
    if not (user['is_seller'] or user['is_admin']):
        flash("You must be a seller or admin to manage products.")
        conn.close()
        return redirect(url_for('home'))

    if request.method == 'POST':
        name = request.form['name']
        price = request.form['price']
        description = request.form['description']

        update_query = f"UPDATE products SET name = '{name}', price = '{price}', description = '{description}' WHERE id = {product_id}"
        conn.execute(update_query)
        conn.commit()
        conn.close()
        
        flash("Product updated successfully!")
        return redirect(url_for('home'))

    product_query = f"SELECT * FROM products WHERE id = {product_id}"
    product = conn.execute(product_query).fetchone()
    conn.close()

    if not product:
        flash("Product not found.")
        return redirect(url_for('home'))

    html = f"""
    <!DOCTYPE html><html><body>
    <h1>Edit Product: {product['name']}</h1>
    <form method="post">
        <label for="name">Product Name</label>
        <input type="text" name="name" id="name" value="{product['name']}" required>
        <br>
        <label for="price">Price</label>
        <input type="number" step="0.01" name="price" id="price" value="{product['price']}" required>
        <br>
        <label for="description">Description</label>
        <textarea name="description" id="description" required>{product['description']}</textarea>
        <br>
        <button type="submit">Save Changes</button>
    </form>
    <br>
    <a href="{url_for('home')}">Cancel</a>
    </body></html>
    """
    return html

@app.route('/delete/<int:product_id>')
def delete_product(product_id):
    logged_in_user = request.cookies.get('username')
    if not logged_in_user:
        flash("You need to be logged in.")
        return redirect(url_for('login'))

    conn = get_db_connection()
    user_query = f"SELECT * FROM users WHERE username = '{logged_in_user}'"
    user = conn.execute(user_query).fetchone()
    
    if not (user['is_seller'] or user['is_admin']):
        flash("You must be a seller or admin to manage products.")
        conn.close()
        return redirect(url_for('home'))

    delete_query = f"DELETE FROM products WHERE id = {product_id}"
    conn.execute(delete_query)
    conn.commit()
    conn.close()
    
    flash("Product deleted successfully.")
    return redirect(url_for('home'))

@app.route('/product/<int:product_id>', methods=('GET', 'POST'))
def product_page(product_id):
    logged_in_user = request.cookies.get('username')
    current_user = None
    
    conn = get_db_connection()
    
    if logged_in_user:
        user_query = f"SELECT * FROM users WHERE username = '{logged_in_user}'"
        current_user = conn.execute(user_query).fetchone()

    if request.method == 'POST':
        if not current_user:
            flash("You must be logged in to leave a review.")
            conn.close()
            return redirect(url_for('login'))
        
        comment = request.form['comment']
        query = f"INSERT INTO reviews (product_id, author_name, comment) VALUES ({product_id}, '{logged_in_user}', '{comment}')"
        conn.execute(query)
        conn.commit()
        flash("Your review has been submitted!")
        
        conn.close()
        return redirect(url_for('product_page', product_id=product_id))

    product_query = f'SELECT * FROM products WHERE id = {product_id}'
    product = conn.execute(product_query).fetchone()
    
    reviews_query = f'SELECT * FROM reviews WHERE product_id = {product_id}'
    reviews = conn.execute(reviews_query).fetchall()
    conn.close() 

    if not product:
        flash("Product not found.")
        return redirect(url_for('home'))

    edit_delete_links = ""
    if current_user:
        if current_user['is_admin'] or (current_user['username'] == product['seller_name']):
            edit_delete_links = f"""
                <p>
                    <a href="{url_for('edit_product', product_id=product['id'])}">Edit Product</a>
                    | <a href="{url_for('delete_product', product_id=product['id'])}">Delete Product</a>
                </p>
            """

    html = f"""
    <!DOCTYPE html><html><body>
    <h1>{product['name']}</h1>
    <p><strong>Price:</strong> £{product['price']}</p>
    <p><strong>Seller:</strong> {product['seller_name']}</p>
    <p>{product['description']}</p>
    
    {edit_delete_links}
    
    <hr>
    <h2>Reviews</h2>
    """
    if reviews:
        for review in reviews:
            html += f"<p><strong>{review['author_name']}:</strong> {review['comment']}</p>"
    else:
        html += "<p>No reviews yet.</p>"

    if logged_in_user:
        html += """
        <h3>Leave a Review</h3>
        <form method="post">
            <textarea name="comment" required></textarea><br>
            <button type="submit">Submit Review</button>
        </form>
        """
        
    html += "<br><a href='/'>Back to Home</a></body></html>"
    return html

@app.route('/admin')
def admin_panel():
    logged_in_user = request.cookies.get('username')
    if not logged_in_user:
        flash("You must be logged in to view this page.")
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    user = conn.execute(f"SELECT * FROM users WHERE username = '{logged_in_user}'").fetchone()
    
    if not user or not user['is_admin']:
        flash("You are not authorised to view this page.")
        conn.close()
        return redirect(url_for('home'))

    users = conn.execute('SELECT id, username FROM users').fetchall()
    products = conn.execute('SELECT id, name FROM products').fetchall()
    conn.close()

    html = f"""
    <!DOCTYPE html>
    <html><head><title>Admin Panel</title></head>
    <body>
        <h1>Admin Panel - Welcome, {user['username']}</h1>
        <h2>Users</h2>
        <ul>
    """
    for u in users:
        html += f"<li>{u['username']}</li>"
    
    html += "</ul><h2>All Products</h2><ul>"

    for p in products:
        html += f"""
        <li>
            {p['name']} 
            <a href="{url_for('delete_product', product_id=p['id'])}">[Delete]</a>
        </li>
        """

    html += "</ul><br><a href='/'>Back to Home</a></body></html>"
    return html

if __name__ == '__main__':
    app.run(debug=True)
    