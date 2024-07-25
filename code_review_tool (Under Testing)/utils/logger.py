import logging

def setup_logger(log_file='code_review_tool.log'):
    logging.basicConfig(
        filename=log_file,
        filemode='a',
        format='%(name)s - %(levelname)s - %(message)s',
        level=logging.INFO
    )
    return logging.getLogger('CodeReviewTool')
