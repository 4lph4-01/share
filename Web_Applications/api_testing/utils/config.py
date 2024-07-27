import os

class Config:
    API_BASE_URL = os.getenv('API_BASE_URL', 'https://api.example.com')
    USERS = {
        "admin": os.getenv('ADMIN_TOKEN'),
        "user1": os.getenv('USER1_TOKEN'),
        "user2": os.getenv('USER2_TOKEN')
    }
    OBJECTS = [1, 2, 3, 4]  # Example object IDs
