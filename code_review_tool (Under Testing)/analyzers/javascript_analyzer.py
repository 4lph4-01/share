import re
from .base_analyzer import BaseAnalyzer

class JavaScriptAnalyzer(BaseAnalyzer):
    def analyze(self, code: str) -> dict:
        issues = []
        lines = code.split('\n')
        for lineno, line in enumerate(lines, start=1):
            if re.search(r'\b(eval|document\.write)\b', line):
                issues.append({
                    'line': lineno,
                    'message': 'Use of eval or document.write detected',
                    'severity': 'high'
                })
        return {'issues': issues}