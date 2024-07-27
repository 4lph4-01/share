import pytest
from utils.api_client import APIClient
from utils.logger import logger

api_client = APIClient()

def test_assets_management():
    response = api_client.get_data(None)  # Check if deprecated endpoint is accessible
    if response.status_code == 200:
        logger.warning(f"Improper Assets Management: Deprecated endpoint is accessible")
    else:
        logger.info(f"Deprecated endpoint access blocked")
    assert response.status_code != 200, "Deprecated endpoints should not be accessible"
