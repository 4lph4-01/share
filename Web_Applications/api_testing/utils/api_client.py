import requests
from .config import Config

class APIClient:
    def __init__(self):
        self.base_url = Config.API_BASE_URL

    def get_object(self, obj_id, token):
        url = f"{self.base_url}/resource/{obj_id}"
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(url, headers=headers)
        return response

    def post_login(self, username, password):
        url = f"{self.base_url}/auth/login"
        data = {"username": username, "password": password}
        response = requests.post(url, json=data)
        return response

    def get_data(self, token):
        url = f"{self.base_url}/data"
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(url, headers=headers)
        return response
