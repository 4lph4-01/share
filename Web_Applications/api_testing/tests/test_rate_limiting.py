import pytest
from utils.api_client import APIClient
from utils.config import Config
from utils.logger import logger

api_client = APIClient()

@pytest.mark.parametrize("user,token", Config.USERS.items())
def test_rate_limiting(user, token):
    for _ in range(100):
        response = api_client.get_data(token)
        if response.status_code == 429:
            logger.info(f"Rate limiting enforced for user {user} after multiple requests")
            break
    else:
        logger.warning(f"Lack of rate limiting: User {user} made 100 requests without rate limiting")
    assert response.status_code != 200, "Rate limiting should enforce limits on repeated requests"
