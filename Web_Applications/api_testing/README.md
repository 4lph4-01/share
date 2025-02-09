# API Testing Framework

This framework automates the testing of OWASP API Top 10 vulnerabilities. By 41lph4-01 and out Community

## Setup

1. Install dependencies:
    ```
    pip install -r requirements.txt
    ```

2. Set environment variables:
    ```
    export API_BASE_URL="https://api.example.com"
    export ADMIN_TOKEN="your_admin_token"
    export USER1_TOKEN="your_user1_token"
    export USER2_TOKEN="your_user2_token"
    ```

3. Run tests:
    ```
    python run_tests.py
    ```

4. Deploy using Gunicorn:
    ```
    gunicorn wsgi:app --workers 4 --bind 0.0.0.0:8000
    ```

## Directory Structure

- `tests/`: Contains test cases for each OWASP API Top 10 vulnerability.
- `utils/`: Contains utility modules such as API client, configuration, and logger.
- `reports/`: Directory for storing test reports.
