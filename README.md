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
- Python 3.12+
- [uv](https://docs.astral.sh/uv/)

#### Installation
1. Clone the repository
2. Set up environment variables
   ```
   cp .env.example .env
   # Edit .env with your configuration
   ```
3. Install dependencies
   ```
   uv sync
   ```
4. Run the application
   ```
   uv run start
   ```
5. Stop the application
   ```
   uv run stop
   ```

### Option 2: Podman Setup

#### Prerequisites
- [Podman](https://podman.io/)
- `podman compose` (or `podman-compose`)

#### Installation
1. Clone the repository

2. Set up environment variables
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. Build and run with Podman Compose
   ```bash
   podman compose up --build
   ```

   Or run in detached mode:
   ```bash
   podman compose up -d
   ```

4. Access the application at `http://localhost:5000` (or your configured port)

#### Environment Variables for Podman
- `PWD_MANAGER_PORT`: Port to expose the application (default: 5000)
- `PWD_MANAGER_DB_PATH`: Path to store the SQLite database (default: ./instance)
- `SECRET_KEY`: Secret key for session management

To stop the Podman container:
```bash
podman compose down
```

> Docker equivalents (`docker compose` / `docker-compose`) work as well.

## Security Notes
- All passwords are encrypted at rest
- Master password is hashed and salted
- Use strong, unique master password
