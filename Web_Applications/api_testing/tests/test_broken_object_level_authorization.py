import pytest
from utils.api_client import APIClient
from utils.config import Config
from utils.logger import logger

api_client = APIClient()

@pytest.mark.parametrize("user,token", Config.USERS.items())
@pytest.mark.parametrize("obj_id", Config.OBJECTS)
def test_broken_object_level_authorization(user, token, obj_id):
    response = api_client.get_object(obj_id, token)
    if response.status_code != 200:
        logger.warning(f"Potential BOLA vulnerability for user {user} accessing object {obj_id}: {response.status_code} - {response.json()}")
    else:
        logger.info(f"Access granted for user {user} to object {obj_id}")
    assert response.status_code == 200, f"User {user} should not have access to object {obj_id}"
