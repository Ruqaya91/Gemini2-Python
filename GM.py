import sqlite3
import os
import secrets
import time
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash

# --- Flask Application Setup ---
app = Flask(__name__)
app.config['DATABASE'] = 'password_reset_app.db' # SQLite database file
app.config['SECRET_KEY'] = secrets.token_hex(16) # A strong secret key for Flask sessions/security
app.config['TOKEN_EXPIRATION_HOURS'] = 1 # Token validity period

# --- Database Helper Functions ---

def get_db():
    """
    Establishes a database connection if one doesn't exist for the current request.
    Stores the connection in Flask's 'g' object.
    """
    if 'db' not in g:
        g.db = sqlite3.connect(
            app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row # Return rows as dictionary-like objects
    return g.db

def close_db(e=None):
    """
    Closes the database connection at the end of the request.
    """
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """
    Initializes the database schema and adds a test user for demonstration.
    """
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.executescript(f.read())
    db.commit()
    print("Database initialized.")

    # Add a test user if they don't exist
    cursor = db.cursor()
    cursor.execute("SELECT id FROM users WHERE email = ?", ("test@example.com",))
    if cursor.fetchone() is None:
        hashed_password = generate_password_hash("password123") # Default password for test user
        db.execute(
            "INSERT INTO users (email, password) VALUES (?, ?)",
            ("test@example.com", hashed_password)
        )
        db.commit()
        print("Test user 'test@example.com' with password 'password123' added.")
    cursor.close()

# Register teardown function to close DB automatically
app.teardown_appcontext(close_db)

# --- Database Schema (schema.sql content) ---
# This schema.sql file will be read by init_db() to set up the database.
# In a real application, you might use a migration tool like Alembic.
SCHEMA_SQL = """
DROP TABLE IF EXISTS password_reset_tokens;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);

CREATE TABLE password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at REAL NOT NULL, -- Unix timestamp
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
"""

# --- API Endpoints ---

@app.route('/request-password-reset', methods=['POST'])
def request_password_reset():
    """
    Allows a user to request a password reset.
    Generates a token and (simulated) sends it to the user's email.
    """
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"message": "Email is required"}), 400

    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        if user:
            user_id = user['id']
            # Generate a secure token
            reset_token = secrets.token_urlsafe(32) # Generates a URL-safe text string
            
            # Calculate expiration time
            expiration_time = datetime.now() + timedelta(hours=app.config['TOKEN_EXPIRATION_HOURS'])
            expires_at_timestamp = expiration_time.timestamp()

            # Invalidate any existing tokens for this user
            db.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (user_id,))

            # Store the new token in the database
            db.execute(
                "INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
                (user_id, reset_token, expires_at_timestamp)
            )
            db.commit()

            # --- Simulate sending email ---
            # In a real application, you would send an email here with a link like:
            # f"https://your-frontend.com/reset-password?token={reset_token}&email={email}"
            print(f"\n--- PASSWORD RESET TOKEN GENERATED ---")
            print(f"For user: {email}")
            print(f"Reset Token: {reset_token}")
            print(f"Expires at: {expiration_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            print(f"--------------------------------------\n")
            # ---------------------------

            # Return a generic success message to prevent user enumeration
            return jsonify({"message": "If an account with that email exists, a password reset link has been sent."}), 200
        else:
            # Still return a generic success message for security
            return jsonify({"message": "If an account with that email exists, a password reset link has been sent."}), 200
    except sqlite3.Error as e:
        db.rollback()
        return jsonify({"message": f"Database error: {e}"}), 500
    finally:
        cursor.close()


@app.route('/reset-password', methods=['POST'])
def reset_password():
    """
    Allows a user to reset their password using a valid token.
    """
    data = request.get_json()
    email = data.get('email')
    token = data.get('token')
    new_password = data.get('new_password')

    if not all([email, token, new_password]):
        return jsonify({"message": "Email, token, and new_password are all required"}), 400

    if len(new_password) < 8: # Basic password policy
        return jsonify({"message": "New password must be at least 8 characters long"}), 400

    db = get_db()
    cursor = db.cursor()
    try:
        # 1. Find the user by email
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"message": "Invalid email or token"}), 400
        user_id = user['id']

        # 2. Find and validate the token
        cursor.execute(
            "SELECT id, expires_at FROM password_reset_tokens WHERE user_id = ? AND token = ?",
            (user_id, token)
        )
        token_record = cursor.fetchone()

        if not token_record:
            return jsonify({"message": "Invalid email or token"}), 400

        token_expires_at = datetime.fromtimestamp(token_record['expires_at'])
        if datetime.now() > token_expires_at:
            # Token expired, delete it
            db.execute("DELETE FROM password_reset_tokens WHERE id = ?", (token_record['id'],))
            db.commit()
            return jsonify({"message": "Token expired"}), 400

        # 3. Hash the new password and update the user's record
        hashed_new_password = generate_password_hash(new_password)
        db.execute(
            "UPDATE users SET password = ? WHERE id = ?",
            (hashed_new_password, user_id)
        )

        # 4. Invalidate the token after successful use
        db.execute("DELETE FROM password_reset_tokens WHERE id = ?", (token_record['id'],))
        db.commit()

        return jsonify({"message": "Password reset successfully"}), 200

    except sqlite3.Error as e:
        db.rollback()
        return jsonify({"message": f"Database error: {e}"}), 500
    finally:
        cursor.close()

# --- Main execution block ---
if __name__ == '__main__':
    # Create schema.sql content
    with open('schema.sql', 'w') as f:
        f.write(SCHEMA_SQL)

    # Initialize the database (create tables and add test user)
    # This will run only when the script is executed directly.
    # In production, you'd run migrations separately.
    with app.app_context():
        init_db()

    print("\n--- Flask Password Reset API ---")
    print("API endpoints:")
    print("1. POST /request-password-reset")
    print("   Body (JSON): {'email': 'user@example.com'}")
    print("   Generates a token and prints it to the console.")
    print("2. POST /reset-password")
    print("   Body (JSON): {'email': 'user@example.com', 'token': 'the_token', 'new_password': 'new_strong_password'}")
    print("\nTo run: python your_script_name.py")
    print("Access the API using a tool like Postman, Insomnia, or curl.")
    print("Example cURL for request-password-reset:")
    print("curl -X POST -H \"Content-Type: application/json\" -d '{\"email\": \"test@example.com\"}' http://127.0.0.1:5000/request-password-reset")
    print("\nExample cURL for reset-password (replace TOKEN with the generated one):")
    print("curl -X POST -H \"Content-Type: application/json\" -d '{\"email\": \"test@example.com\", \"token\": \"<THE_GENERATED_TOKEN>\", \"new_password\": \"newsecurepass\"}' http://127.0.0.1:5000/reset-password")
    print("\nStarting Flask server...")
    app.run(debug=True) # debug=True is for development, set to False in production
