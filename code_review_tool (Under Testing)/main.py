import os
import argparse
import logging
from analyzers.python_analyzer import PythonAnalyzer
from analyzers.javascript_analyzer import JavaScriptAnalyzer
from config.config import load_config
from reports.report_generator import ReportGenerator
from utils.logger import setup_logger
from utils.error_handler import handle_error

def get_analyzer(file_extension, config):
    analyzers = {
        '.py': PythonAnalyzer(config),
        '.js': JavaScriptAnalyzer(config),
    }
    return analyzers.get(file_extension)

def analyze_file(filepath, config):
    _, file_extension = os.path.splitext(filepath)
    analyzer = get_analyzer(file_extension, config)
    if not analyzer:
        logging.info(f"No analyzer available for {file_extension}")
        return []

    with open(filepath, 'r') as file:
        code = file.read()

    return analyzer.analyze(code)['issues']

def main():
    parser = argparse.ArgumentParser(description='Code Review Tool')
    parser.add_argument('directory', help='Directory to analyze')
    parser.add_argument('--config', help='Path to configuration file', default='config/config.json')
    parser.add_argument('--report', help='Output report format (json, html)', default='json')
    args = parser.parse_args()

    logger = setup_logger()
    config = load_config(args.config)
    all_issues = []

    try:
        for root, _, files in os.walk(args.directory):
            for file in files:
                filepath = os.path.join(root, file)
                issues = analyze_file(filepath, config)
                for issue in issues:
                    issue['file'] = filepath
                all_issues.extend(issues)
    except Exception as e:
        handle_error(e)

    report = ReportGenerator.generate_report(all_issues, args.report)
    print(report)

if __name__ == '__main__':
    main()