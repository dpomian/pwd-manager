# Secure Password Manager

## Overview
A web-based password manager that allows secure storage and management of your passwords.

## Features
- Secure user registration and authentication
- Encrypted password storage
- Add, view, edit, and delete password entries
- Master password protection

## Setup Instructions

### Option 1: Local Setup

#### Prerequisites
- Python 3.8+
- pip

#### Installation
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

### Option 2: Docker Setup

#### Prerequisites
- Docker
- Docker Compose

#### Installation
1. Clone the repository

2. Set up environment variables
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. Build and run with Docker Compose
   ```bash
   docker-compose up --build
   ```

   Or run in detached mode:
   ```bash
   docker-compose up -d
   ```

4. Access the application at `http://localhost:5000` (or your configured port)

#### Environment Variables for Docker
- `PWD_MANAGER_PORT`: Port to expose the application (default: 5000)
- `PWD_MANAGER_DB_PATH`: Path to store the SQLite database (default: ./instance)
- `SECRET_KEY`: Secret key for session management

To stop the Docker container:
```bash
docker-compose down
```

## Security Notes
- All passwords are encrypted at rest
- Master password is hashed and salted
- Use strong, unique master password
