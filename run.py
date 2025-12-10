import argparse
import os

# Parse args before creating app so we can set env file
parser = argparse.ArgumentParser(description="Run the Password Manager app")
parser.add_argument(
    "-p",
    "--port",
    type=int,
    default=5000,
    help="Port to run the app on (default: 5000)",
)
parser.add_argument(
    "-e",
    "--env",
    type=str,
    default=None,
    help="Path to .env file to use (e.g., .env.local, .env.production)",
)

args, _ = parser.parse_known_args()

# Set env file path before importing create_app
if args.env:
    os.environ['PWD_MANAGER_ENV_FILE'] = args.env

from pwd_manager import create_app

app = create_app()

if __name__ == "__main__":
    app.run(debug=True, port=args.port)
