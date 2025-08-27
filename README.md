# Secure Token Management System
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A powerful and secure system for managing authentication tokens in Python.

## ✨ Features

- 🔒 **High Security**: AES-128 encryption with Fernet
- 🎯 **Easy to Use**: Simple and intuitive API
- ⚡ **High Performance**: Optimized for production use
- 🗄️ **Database Support**: SQLite, PostgreSQL, MySQL
- 🔄 **Auto-Renewal**: Intelligent token expiration management
- 📊 **Comprehensive Monitoring**: Advanced logging and reporting

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