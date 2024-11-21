# Secure Password Manager

## Overview
A web-based password manager that allows secure storage and management of your passwords.

## Features
- Secure user registration and authentication
- Encrypted password storage
- Add, view, edit, and delete password entries
- Master password protection

## Setup Instructions

### Prerequisites
- Python 3.8+
- pip

### Installation
1. Clone the repository
2. Create a virtual environment
   ```
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install dependencies
   ```
   pip install -r requirements.txt
   ```
4. Set up environment variables
   ```
   cp .env.example .env
   # Edit .env with your configuration
   ```
5. Run the application
   ```
   flask run
   ```

## Security Notes
- All passwords are encrypted at rest
- Master password is hashed and salted
- Use strong, unique master password
