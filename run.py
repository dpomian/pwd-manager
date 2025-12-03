from pwd_manager import create_app

app = create_app()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Run the Password Manager app")
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=5000,
        help="Port to run the app on (default: 5000)",
    )
    
    args = parser.parse_args()
    app.run(debug=True, port=args.port)
