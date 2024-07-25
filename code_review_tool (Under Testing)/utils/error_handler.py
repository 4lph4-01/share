import logging

def handle_error(error):
    logger = logging.getLogger('CodeReviewTool')
    logger.error(f"An error occurred: {error}")