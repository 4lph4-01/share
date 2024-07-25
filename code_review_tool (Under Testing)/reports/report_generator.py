import json

class ReportGenerator:
    @staticmethod
    def generate_report(issues, output_format='json'):
        if output_format == 'json':
            return json.dumps(issues, indent=4)
        elif output_format == 'html':
            html = "<html><body><h1>Code Review Report</h1><ul>"
            for issue in issues:
                html += f"<li>{issue['file']}:{issue['line']} - {issue['message']} ({issue['severity']})</li>"
            html += "</ul></body></html>"
            return html
        else:
            raise ValueError("Unsupported report format")
