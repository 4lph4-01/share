import pytest
from utils.api_client import APIClient
from utils.logger import logger

api_client = APIClient()

def test_mass_assignment():
    data = {
        "username": "new_user",
        "password": "password",
        "role": "admin"  # Role should not be assignable by client
    }
    response = api_client.post_data(data)
    if response.status_code == 200 and response.json().get("role") == "admin":
        logger.warning(f"Mass Assignment vulnerability: Role assigned via client input")
    else:
        logger.info(f"Mass Assignment attempt blocked")
    assert response.status_code != 200, "Mass assignment should not be allowed"
