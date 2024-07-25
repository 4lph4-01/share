import logging

class BaseAnalyzer:
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)

    def analyze(self, code: str) -> dict:
        raise NotImplementedError("Subclasses should implement this!")

    def get_configured_rules(self):
        return self.config.get(self.__class__.__name__, {}).get('rules', [])