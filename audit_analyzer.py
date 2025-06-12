import os
import re
import httpx
from openai import OpenAI

class AuditAnalyzer:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.environ.get('OPENROUTER_API_KEY')
        if self.api_key:
            self.client = OpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=self.api_key,
                http_client=httpx.Client()  
            )
        else:
            self.client = None
    
    def analyze_report(self, report_content):
        """
        Analyze the audit report using available methods (AI or local)
        """
        try:
            if self.client:
                return self._analyze_with_openai(report_content)
            else:
                return self._analyze_locally(report_content)
        except Exception as e:
            print(f"Error analyzing report: {str(e)}")
            return self._fallback_analysis(report_content)
    
    def _analyze_with_openai(self, report_content):
        prompt = f"""
        Analyze the following Linux system audit report and provide:

        1. A brief summary of the overall system security status.
        2. The most critical findings that need immediate attention.
        3. Specific, actionable recommendations to address each critical finding listed above.

        Report:
        {report_content[:4000]}
        """
        
        try:
            response = self.client.chat.completions.create(
                extra_headers={
                    "HTTP-Referer": "http://localhost:5000",
                    "X-Title": "System Audit Tool",
                },
                model="deepseek/deepseek-prover-v2:free",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in Linux system security audits."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1500  
            )
            analysis_text = response.choices[0].message.content
            print("AI Response:\n", analysis_text)  # لمساعدتك في التحقق
            return self._parse_ai_response(analysis_text)
        except Exception as e:
            print(f"Error using OpenRouter: {str(e)}")
            return self._fallback_analysis(report_content)




    def _parse_ai_response(self, response_text):
        """
        Parse the AI response into structured sections.
        """
        # Initialize sections
        sections = {
            'summary': '',
            'critical_findings': [],
            'recommendations': []
        }
        
        # Simple parsing based on common patterns in the response
        if 'summary' in response_text.lower():
            summary_match = re.search(r'(?:summary|overview):(.*?)(?:\n\n|\n\d\.|\Z)', 
                                     response_text.lower(), re.DOTALL | re.IGNORECASE)
            if summary_match:
                sections['summary'] = summary_match.group(1).strip()
        
        # Extract critical findings
        findings_pattern = r'(?:critical findings|key issues|immediate attention):(.*?)(?:\n\n|\n\d\.|\Z)'
        findings_match = re.search(findings_pattern, response_text.lower(), re.DOTALL | re.IGNORECASE)
        if findings_match:
            findings_text = findings_match.group(1).strip()
            # Split by bullet points or numbers
            findings = re.split(r'\n\s*[-*•]|\n\s*\d+\.', findings_text)
            sections['critical_findings'] = [f.strip() for f in findings if f.strip()]
        
        # Extract recommendations
        recommendations_pattern = r'(?:recommendations|suggested actions):(.*?)(?:\n\n|\Z)'
        recommendations_match = re.search(recommendations_pattern, response_text.lower(), re.DOTALL | re.IGNORECASE)
        if recommendations_match:
            recommendations_text = recommendations_match.group(1).strip()
            # Split by bullet points or numbers
            recommendations = re.split(r'\n\s*[-*•]|\n\s*\d+\.', recommendations_text)
            sections['recommendations'] = [r.strip() for r in recommendations if r.strip()]
        
        # If parsing failed, use the whole response as summary
        if not sections['summary'] and not sections['critical_findings'] and not sections['recommendations']:
            sections['summary'] = response_text.strip()
        
        return sections
    
    def _analyze_locally(self, report_content):
        """
        Perform a local analysis of the report without using external APIs.
        This is a simplified analysis based on pattern matching.
        """
        sections = {
            'summary': '',
            'critical_findings': [],
            'recommendations': []
        }
        
        # Count warnings and critical issues
        warning_count = len(re.findall(r'WARNING:', report_content, re.IGNORECASE))
        critical_count = len(re.findall(r'CRITICAL:', report_content, re.IGNORECASE))
        
        # Generate a basic summary
        sections['summary'] = f"The system audit found {warning_count} warnings and {critical_count} critical issues that need attention."
        
        # Extract critical findings
        critical_findings = re.findall(r'(CRITICAL:.*?)(?:\n[^\n]|\Z)', report_content, re.IGNORECASE)
        warnings = re.findall(r'(WARNING:.*?)(?:\n[^\n]|\Z)', report_content, re.IGNORECASE)
        
        # Add critical findings first, then warnings if we have space
        sections['critical_findings'] = critical_findings[:5]  # Limit to top 5
        if len(sections['critical_findings']) < 5:
            sections['critical_findings'].extend(warnings[:5-len(sections['critical_findings'])])
        
        # Extract recommendations from the report
        recommendations = []
        recommendation_sections = re.findall(r'Recommendations:(.*?)(?:\n\n|\Z)', report_content, re.DOTALL)
        for section in recommendation_sections:
            # Extract bullet points
            bullets = re.findall(r'-\s*(.*?)(?:\n-|\Z)', section, re.DOTALL)
            recommendations.extend(bullets)
        
        sections['recommendations'] = recommendations[:7]  # Limit to top 7
        
        return sections
    
    def _fallback_analysis(self, report_content):
        """
        Provide a very basic analysis when other methods fail.
        """
        return {
            'summary': "An audit of the system was performed. Please review the full report for details.",
            'critical_findings': ["Unable to automatically identify critical findings. Please review the full report."],
            'recommendations': [
                "Review the complete audit report for detailed findings",
                "Address any WARNING or CRITICAL items mentioned in the report",
                "Consider running a follow-up audit after making changes"
            ]
        }
    
    def format_analysis_html(self, analysis):
        """
        Format the analysis results as HTML for display in the web interface.
        
        Args:
            analysis (dict): The analysis results from analyze_report()
            
        Returns:
            str: HTML formatted analysis
        """
        html = f"<p><strong>Summary:</strong> {analysis['summary']}</p>"
        
        if analysis['critical_findings']:
            html += "<p><strong>Critical Findings:</strong></p><ul>"
            for finding in analysis['critical_findings']:
                html += f"<li>{finding}</li>"
            html += "</ul>"
        
        if analysis['recommendations']:
            html += "<p><strong>Recommendations:</strong></p><ul>"
            for recommendation in analysis['recommendations']:
                html += f"<li>{recommendation}</li>"
            html += "</ul>"
        
        return html

