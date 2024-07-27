import pytest
from utils.api_client import APIClient
from utils.config import Config
from utils.logger import logger

api_client = APIClient()

@pytest.mark.parametrize("user,token", Config.USERS.items())
def test_excessive_data_exposure(user, token):
    response = api_client.get_data(token)
    data = response.json()
    if "sensitive_info" in data:
        logger.warning(f"Excessive Data Exposure for user {user}: {data}")
    assert "sensitive_info" not in data, "Sensitive information should not be exposed"
