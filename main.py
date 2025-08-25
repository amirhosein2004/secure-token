# main.py
from src import get_message
import time
if __name__ == "__main__":
    while True:
        message = get_message()
        print("Docker test is running...")
        print(f"Message from src: {message}")
        print("Test is successful if you see this message.")
        time.sleep(5)