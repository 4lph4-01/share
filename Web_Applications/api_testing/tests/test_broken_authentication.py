import pytest
from utils.api_client import APIClient
from utils.logger import logger

api_client = APIClient()

def test_broken_authentication():
    response = api_client.post_login("invalid_user", "invalid_password")
    if response.status_code == 200:
        logger.warning(f"Broken Authentication vulnerability: Logged in with invalid credentials: {response.json()}")
    else:
        logger.info(f"Authentication failed as expected with invalid credentials")
    assert response.status_code != 200, "Authentication should fail with invalid credentials"
