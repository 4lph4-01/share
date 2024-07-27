import pytest
from utils.api_client import APIClient
from utils.config import Config
from utils.logger import logger

api_client = APIClient()

@pytest.mark.parametrize("user,token", Config.USERS.items())
def test_injection(user, token):
    payload = "' OR '1'='1"
    response = api_client.get_object(payload, token)
    if response.status_code == 200:
        logger.warning(f"Injection vulnerability: User {user} accessed object with payload: {payload}")
    else:
        logger.info(f"Injection attempt blocked for user {user}")
    assert response.status_code != 200, "Injection should not grant access to objects"
