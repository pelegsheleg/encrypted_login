# README for User Authentication Script

## Overview
This script implements a user authentication system using a graphical user interface (GUI) created with Tkinter in Python. It connects to a MySQL database to store and verify user credentials. The script provides features for user login, user registration, password strength validation, and secure password storage using hashing and salting techniques.

## Features
- **User Login**: Allows existing users to log in by verifying their credentials.
- **User Registration**: New users can create an account by providing a username and password.
- **Password Strength Check**: Validates the strength of the passwords during registration.
- **Secure Password Storage**: Uses `hashlib` and `binascii` for hashing and salting passwords before storing them in the database.
- **User Interface**: Built using Tkinter, providing a simple and interactive GUI for users.

## Requirements
- Python 3.x
- Tkinter library (usually comes with Python)
- `mysql.connector` for MySQL database connection
- MySQL Database

## Installation
1. Install Python 3.x from [Python's official website](https://www.python.org/).
2. Ensure Tkinter is installed. It's included in the standard Python installation. If not, install it using your package manager.
3. Install `mysql.connector` using pip:
   ```
   pip install mysql-connector-python
   ```
4. Set up a MySQL database and create a table for storing user data.

## Database Setup
- Create a database named `logininfo`.
- Inside the database, create a table named `users_data` with columns `user`, `password`, and `salt`.

## Usage
Run the script using Python:
```
python script_name.py
```
- On launching, the main window will provide options to log in, register a new user, or exit the application.
- For registration, the system checks for password strength and uniqueness of the username.
- For login, the system validates the entered credentials against the stored data in the MySQL database.

## Security Features
- Passwords are hashed using SHA-256 and a unique salt for each user.
- The script checks for common and weak passwords to ensure password strength.

## Limitations
- The GUI is basic and may not be visually appealing for all users.
- Currently, there's no functionality to handle forgotten passwords or change existing passwords.

## Contributions
Contributions to this project are welcome. Please ensure to follow best practices for code style and security enhancements.
