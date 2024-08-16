from flask import Flask, render_template, request, redirect, url_for, session, flash
import rsa
import csv
import time
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Check if the public and private key files exist
public_key_exists = os.path.isfile('public_key.pem')
private_key_exists = os.path.isfile('private_key.pem')

if not public_key_exists or not private_key_exists:
    # Generate RSA keys if they do not exist
    (pubkey, privkey) = rsa.newkeys(512)
    with open('public_key.pem', 'wb') as pub_file:
        pub_file.write(pubkey.save_pkcs1('PEM'))
    with open('private_key.pem', 'wb') as priv_file:
        priv_file.write(privkey.save_pkcs1('PEM'))
    print('Keys generated and saved to public_key.pem and private_key.pem.')
else:
    # Load RSA keys from files
    with open('public_key.pem', 'rb') as pub_file:
        pubkey = rsa.PublicKey.load_pkcs1(pub_file.read())
    with open('private_key.pem', 'rb') as priv_file:
        privkey = rsa.PrivateKey.load_pkcs1(priv_file.read())
    print('Keys loaded from existing files.')

# User attempts tracking
user_attempts = {}

# Function to load a user's public key
def load_user_public_key(username):
    with open(f'{username}_public_key.pem', 'rb') as pub_file:
        return rsa.PublicKey.load_pkcs1(pub_file.read())
        
def load_user_private_key(username):
    with open(f'{username}_private_key.pem', 'rb') as priv_file:
        return rsa.PrivateKey.load_pkcs1(priv_file.read())

def create_user_keys(username):
    pubkey, privkey = rsa.newkeys(512)
    # Save the public key
    with open(f'{username}_public_key.pem', 'wb') as pub_file:
        pub_file.write(pubkey.save_pkcs1('PEM'))
    # Save the private key
    with open(f'{username}_private_key.pem', 'wb') as priv_file:
        priv_file.write(privkey.save_pkcs1('PEM'))
    print(f'Keys for {username} generated and saved.')

# Function to save user credentials
def save_user(username, password):
    encrypted_password = rsa.encrypt(password.encode(), pubkey)
    with open('users.csv', 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([username, encrypted_password])

# Function to verify user credentials
def verify_user(username, password):
    with open('users.csv', 'r') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            stored_username, stored_encrypted_password = row
            if stored_username == username:
                try:
                    decrypted_password = rsa.decrypt(eval(stored_encrypted_password), privkey).decode()
                    return decrypted_password == password
                except:
                    return False
    return False

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Initialize user attempts if not present
        if username not in user_attempts:
            user_attempts[username] = {'attempts': 0, 'blocked': False, 'last_attempt': 0}

        # Check if user is blocked
        if user_attempts[username]['blocked']:
            current_time = time.time()
            if user_attempts[username]['attempts'] >= 5:
                return render_template('login.html', message='Account locked. Please contact the administrator.')
            elif current_time - user_attempts[username]['last_attempt'] < 60:
                return render_template('login.html', message='Too many attempts. Please try again after 60 seconds.')
            else:
                # Reset block after 60 seconds
                user_attempts[username]['blocked'] = False

        if verify_user(username, password):
            session['username'] = username
            user_attempts[username] = {'attempts': 0, 'blocked': False, 'last_attempt': 0}
            return redirect(url_for('welcome'))
        else:
            user_attempts[username]['attempts'] += 1
            user_attempts[username]['last_attempt'] = time.time()

            if user_attempts[username]['attempts'] >= 5:
                user_attempts[username]['blocked'] = True
                return render_template('login.html', message='Account locked. Please contact the administrator.')
            elif user_attempts[username]['attempts'] >= 3:
                user_attempts[username]['blocked'] = True
                return render_template('login.html', message='Too many attempts. Please try again after 60 seconds.')

            return render_template('login.html', message='Invalid credentials')
    return render_template('login.html')

@app.route('/welcome', methods=['GET', 'POST'])
def welcome():
    decrypted_message = session.pop('decrypted_message', None)
    if 'username' in session:
        return render_template('welcome.html', username=session['username'], decrypted_message=decrypted_message)
    return redirect(url_for('login'))

@app.route('/save_message', methods=['POST'])
def save_message():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user_message = request.form['user_message']
    pubkey = load_user_public_key(username)

    # Encrypt the message
    encrypted_message = rsa.encrypt(user_message.encode(), pubkey)

    # Save the encrypted message to a text file
    with open(f'{username}_message.txt', 'wb') as message_file:
        message_file.write(encrypted_message)

    return redirect(url_for('welcome'))

@app.route('/decrypt_message', methods=['POST'])
def decrypt_message():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    privkey = load_user_private_key(username)

    # Check if a file was uploaded
    if 'encrypted_file' not in request.files:
        return redirect(url_for('welcome'))

    file = request.files['encrypted_file']

    # Check if the file is valid
    if file.filename == '':
        return redirect(url_for('welcome'))

    try:
        # Read the encrypted message from the file
        encrypted_message = file.read()

        # Decrypt the message
        decrypted_message = rsa.decrypt(encrypted_message, privkey).decode()

        # Store the decrypted message in the session
        session['decrypted_message'] = decrypted_message
    except Exception as e:
        session['decrypted_message'] = f'Error decrypting message: {str(e)}'

    return redirect(url_for('welcome')) 

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Create and save keys for the new user
        create_user_keys(username)
        # Save the user credentials
        save_user(username, password)
        return redirect(url_for('login'))
    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True)
