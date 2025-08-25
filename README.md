# Secure Token Management System

This project provides a robust and secure system for generating, validating, and managing cryptographic tokens, similar in concept to JWT. It is designed to be secure, flexible, and easy to integrate into various Python applications.

## Docker Deployment

The application is fully containerized. You can build and run it using Docker.

1.  **Build the Docker image:**
    From the root directory of the project, run:
    ```bash
    docker build -t name-of-image:tag .
    ```

2.  **Run the container:**
    This will run the `main.py` script inside the container.
    ```bash
    docker run -d -p 8000:8000 --name name-of-container name-of-image:tag
    ```

This will start the application and, based on the current `main.py`, print a test message every 5 seconds.
