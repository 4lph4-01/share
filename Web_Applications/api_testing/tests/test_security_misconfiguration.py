import pytest
from utils.api_client import APIClient
from utils.logger import logger

api_client = APIClient()

def test_security_misconfiguration():
    response = api_client.get_data(None)  # No token provided
    if response.status_code == 200:
        logger.warning(f"Security Misconfiguration: Access granted without authentication")
    else:
        logger.info(f"Access denied as expected without authentication")
    assert response.status_code != 200, "Access should be denied without authentication"
