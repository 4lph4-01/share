import ast
from .base_analyzer import BaseAnalyzer

class PythonAnalyzer(BaseAnalyzer):
    def analyze(self, code: str) -> dict:
        issues = []
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name == 'os':
                            issues.append({
                                'line': node.lineno,
                                'message': 'Potentially dangerous import of "os" module',
                                'severity': 'medium'
                            })
        except SyntaxError as e:
            issues.append({
                'line': e.lineno,
                'message': 'Syntax error',
                'severity': 'high'
            })
        return {'issues': issues}
