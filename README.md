# Enhanced Linux System Audit Tool

This project is a Flask-based web application that runs system security audits on Linux servers. It has been enhanced with several new features to improve security assessment and reporting capabilities.

## Features

### 1. Password Security Checks
- Detects empty or default passwords
- Checks /etc/shadow permissions and exposure
- Scans for plaintext passwords in config files
- Evaluates password policy settings

### 2. Email Report Delivery
- Prompts for email address after audit completion
- Converts audit reports to HTML or PDF format
- Sends formatted reports as email attachments
- Includes summary in the email body

### 3. AI Summary & Recommendations
- Analyzes audit results using AI (OpenAI API or local analysis)
- Extracts critical findings from the report
- Generates actionable recommendations
- Displays AI insights in the dashboard and includes them in emailed reports

### 4. SSH Remote Audit Support
- Allows auditing of remote machines via SSH
- Supports both password and key-based authentication
- Securely uploads and executes the audit script remotely
- Fetches and processes remote audit results

## Setup Instructions

1. Install the required dependencies:
```
pip install -r requirements.txt
```

2. Configure email settings in app.py:
```python
app.config['MAIL_SERVER'] = 'your_smtp_server'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'your_email@example.com'
app.config['MAIL_PASSWORD'] = 'your_app_password'
app.config['MAIL_DEFAULT_SENDER'] = ('System Audit', 'your_email@example.com')
```

3. (Optional) Set your OpenAI API key for enhanced AI analysis:
```python
os.environ['OPENAI_API_KEY'] = 'your-openai-api-key'
```

4. Run the application:
```
python app.py
```

5. Access the web interface at http://localhost:5000

## Usage

### Local Audit
1. Log in to the dashboard
2. Click "Run New Audit" to perform a local system audit
3. Review the results in the dashboard
4. Click "Send Report via Email" to send the report to your email

### Remote Audit
1. Navigate to the "Remote Audit" page from the sidebar
2. Enter the SSH connection details for the remote server
3. Run the audit and review the results
4. Send the report via email if desired

## Notes
- The application requires sudo privileges to run the audit script
- For remote audits, the SSH user must have sudo privileges on the remote server
- If not using OpenAI API, the system will fall back to local pattern-based analysis
- Email functionality requires valid SMTP server credentials

## Files
- `app.py`: Main Flask application
- `system_audit.sh`: Bash script that performs the system audit
- `audit_analyzer.py`: AI-powered analysis of audit reports
- `remote_audit.py`: Handles SSH connections and remote script execution
- `templates/`: HTML templates for the web interface
