from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import os
import subprocess
import datetime
import re
import tempfile
from flask_mail import Mail, Message
from weasyprint import HTML, CSS
import io
from audit_analyzer import AuditAnalyzer

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a random secret key in production

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Change to your SMTP server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = ''  # Change to your email
app.config['MAIL_PASSWORD'] = ''  # Change to your app password
app.config['MAIL_DEFAULT_SENDER'] = ('System Audit', 'your_email@gmail.com')
mail = Mail(app)

# Initialize the AI audit analyzer
# You can set your OpenAI API key here or as an environment variable
os.environ['OPENROUTER_API_KEY'] = ''  # بدلاً من OPENAI_API_KEY
analyzer = AuditAnalyzer()

# Create templates directory if it doesn't exist
os.makedirs('templates', exist_ok=True)



@app.route('/')
def index():
    if 'logged_in' in session and session['logged_in']:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username == 'admin' and password == 'password':
        session['logged_in'] = True
        session['username'] = username
        return redirect(url_for('dashboard'))
    else:
        return render_template('login.html', error='Invalid credentials')

@app.route('/dashboard')
def dashboard():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('index'))
    
    system_stats = {
        'passed': 12,
        'failed': 3,
        'warning': 5,
        'total': 20
    }
    
    recent_issues = [
        {'check': 'File Permissions', 'status': 'Failed', 'details': '/etc/shadow has overly permissive permissions'},
        {'check': 'Open Ports', 'status': 'Warning', 'details': 'Port 22 (SSH) is open to all IPs'},
        {'check': 'User Accounts', 'status': 'Passed', 'details': 'No unauthorized users detected'},
        {'check': 'Software Updates', 'status': 'Warning', 'details': '5 security updates available'}
    ]
    
    return render_template('dashboard.html', stats=system_stats, issues=recent_issues)


@app.route('/run_audit', methods=['POST'])
def run_audit():
    if 'logged_in' not in session or not session['logged_in']:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Path to the audit script
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'system_audit.sh')
        
        # Make sure the script is executable
        os.chmod(script_path, 0o755)
        
        # Run the script - note this requires sudo permissions
        # In a real environment, you'd need to handle sudo differently
        # This is just for demonstration purposes
        process = subprocess.Popen(['sudo', script_path], 
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            # Get the name of the generated report file
            report_pattern = re.compile(r'system_audit_report_\d{8}_\d{6}\.txt')
            report_files = [f for f in os.listdir('.') if report_pattern.match(f)]
            
            if report_files:
                # Sort by creation time, newest first
                latest_report = sorted(report_files, key=lambda x: os.path.getctime(x), reverse=True)[0]
                
                with open(latest_report, 'r') as f:
                    report_content = f.read()
                
                # Store the report file path in the session for email sending
                session['latest_report'] = latest_report
                
                # Generate AI summary and recommendations
                analysis = analyzer.analyze_report(report_content)
                ai_summary_html = analyzer.format_analysis_html(analysis)
                
                # Store the AI summary in the session for email sending
                session['ai_summary'] = analysis
                session['ai_summary_html'] = ai_summary_html
                
                return jsonify({
                    'success': True,
                    'message': 'Audit completed successfully',
                    'report': report_content,
                    'report_file': latest_report,
                    'ai_summary': ai_summary_html
                })
            else:
                return jsonify({
                    'success': False,
                    'message': 'Audit completed but report file not found'
                })
        else:
            return jsonify({
                'success': False,
                'message': 'Audit failed',
                'error': stderr.decode('utf-8')
            })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'message': 'An error occurred',
            'error': str(e)
        })

@app.route('/email_form')
def email_form():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('index'))
    
    if 'latest_report' not in session:
        flash('No audit report available. Please run an audit first.')
        return redirect(url_for('dashboard'))
    
    return render_template('email_form.html')

@app.route('/send_report', methods=['POST'])
def send_report():
    if 'logged_in' not in session or not session['logged_in']:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    if 'latest_report' not in session:
        return jsonify({'success': False, 'message': 'No audit report available. Please run an audit first.'})
    
    email = request.form.get('email')
    report_format = request.form.get('format', 'pdf')
    
    if not email:
        return jsonify({'success': False, 'message': 'Email address is required'})
    
    try:
        report_file = session['latest_report']
        
        with open(report_file, 'r') as f:
            report_content = f.read()
        
        # Get AI summary if available
        ai_summary_html = ""
        if 'ai_summary_html' in session and session['ai_summary_html']:
            ai_summary_html = session['ai_summary_html']
        elif 'ai_summary' in session and session['ai_summary']:
            # Format the summary if we have the raw data but not HTML
            ai_summary = session['ai_summary']
            ai_summary_html = f"""
            <div class="ai-summary">
                <h2>AI Analysis</h2>
                <p><strong>Summary:</strong> {ai_summary.get('summary', '')}</p>
                
                <h3>Critical Findings:</h3>
                <ul>
                    {"".join([f"<li>{finding}</li>" for finding in ai_summary.get('critical_findings', [])])}
                </ul>
                
                <h3>Recommendations:</h3>
                <ul>
                    {"".join([f"<li>{rec}</li>" for rec in ai_summary.get('recommendations', [])])}
                </ul>
            </div>
            """
        
        # Extract a brief summary from the report (first few lines)
        summary_lines = report_content.split('\n')[:10]
        summary = '\n'.join(summary_lines)
        
        # Create email message with AI summary if available
        email_body = f"Please find attached your system audit report.\n\nSummary:\n{summary}\n\n"
        if 'ai_summary' in session and session['ai_summary']:
            ai_summary = session['ai_summary']
            email_body += "\nAI ANALYSIS:\n"
            email_body += f"Summary: {ai_summary.get('summary', '')}\n\n"
            
            if ai_summary.get('critical_findings'):
                email_body += "Critical Findings:\n"
                for i, finding in enumerate(ai_summary.get('critical_findings', []), 1):
                    email_body += f"{i}. {finding}\n"
                email_body += "\n"
            
            if ai_summary.get('recommendations'):
                email_body += "Recommendations:\n"
                for i, rec in enumerate(ai_summary.get('recommendations', []), 1):
                    email_body += f"{i}. {rec}\n"
        
        email_body += "\nPlease review the full report for details and recommendations."
        
        msg = Message(
            subject='System Audit Report',
            recipients=[email],
            body=email_body
        )
        
        # Convert report to requested format and attach
        if report_format == 'pdf':
            # Create HTML version of the report with AI summary
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>System Audit Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                    h1 {{ color: #2d3748; }}
                    h2 {{ color: #4a5568; margin-top: 20px; }}
                    pre {{ background-color: #f8f9fa; padding: 10px; border-radius: 5px; white-space: pre-wrap; }}
                    .section {{ margin-bottom: 20px; border-bottom: 1px solid #e2e8f0; padding-bottom: 10px; }}
                    .warning {{ color: #e53e3e; }}
                    .passed {{ color: #38b2ac; }}
                    .ai-summary {{ 
                        background-color: #f0f9ff; 
                        padding: 15px; 
                        border-radius: 6px;
                        border-left: 4px solid #4299e1;
                        margin: 20px 0;
                    }}
                    .ai-summary h2 {{ color: #2b6cb0; margin-top: 0; }}
                    .ai-summary ul {{ margin-bottom: 15px; }}
                </style>
            </head>
            <body>
                <h1>System Audit Report</h1>
                
                {ai_summary_html}
                
                <h2>Full Audit Report</h2>
                <pre>{report_content}</pre>
            </body>
            </html>
            """
            
            # Convert HTML to PDF
            pdf_file = io.BytesIO()
            HTML(string=html_content).write_pdf(pdf_file)
            pdf_file.seek(0)
            
            # Attach PDF to email
            msg.attach(
                'system_audit_report.pdf',
                'application/pdf',
                pdf_file.read()
            )
        else:  # HTML format
            # Create HTML version of the report with AI summary
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>System Audit Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                    h1 {{ color: #2d3748; }}
                    h2 {{ color: #4a5568; margin-top: 20px; }}
                    pre {{ background-color: #f8f9fa; padding: 10px; border-radius: 5px; white-space: pre-wrap; }}
                    .section {{ margin-bottom: 20px; border-bottom: 1px solid #e2e8f0; padding-bottom: 10px; }}
                    .warning {{ color: #e53e3e; }}
                    .passed {{ color: #38b2ac; }}
                    .ai-summary {{ 
                        background-color: #f0f9ff; 
                        padding: 15px; 
                        border-radius: 6px;
                        border-left: 4px solid #4299e1;
                        margin: 20px 0;
                    }}
                    .ai-summary h2 {{ color: #2b6cb0; margin-top: 0; }}
                    .ai-summary ul {{ margin-bottom: 15px; }}
                </style>
            </head>
            <body>
                <h1>System Audit Report</h1>
                
                {ai_summary_html}
                
                <h2>Full Audit Report</h2>
                <pre>{report_content}</pre>
            </body>
            </html>
            """
            
            # Attach HTML to email
            msg.html = html_content
        
        # Send email
        mail.send(msg)
        
        return jsonify({'success': True, 'message': f'Report sent to {email}'})
    
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error sending email: {str(e)}'})

@app.route('/remote_audit')
def remote_audit():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('index'))
    
    return render_template('remote_audit.html')

@app.route('/run_remote_audit', methods=['POST'])
def run_remote_audit():
    if 'logged_in' not in session or not session['logged_in']:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    # Get connection details from form
    hostname = request.form.get('hostname')
    port = int(request.form.get('port', 22))
    username = request.form.get('username')
    auth_method = request.form.get('auth_method')
    password = request.form.get('password') if auth_method == 'password' else None
    key_path = request.form.get('key_path') if auth_method == 'key' else None
    
    # Validate required fields
    if not hostname or not username:
        return jsonify({'success': False, 'message': 'Hostname and username are required'})
    
    if auth_method == 'password' and not password:
        return jsonify({'success': False, 'message': 'Password is required for password authentication'})
    
    if auth_method == 'key' and not key_path:
        return jsonify({'success': False, 'message': 'Key path is required for key-based authentication'})
    
    try:
        # Import the remote audit manager
        from remote_audit import RemoteAuditManager
        
        # Initialize the remote audit manager
        remote_manager = RemoteAuditManager()
        
        # Connect to the remote server
        if not remote_manager.connect(hostname, username, password, key_path, port):
            return jsonify({'success': False, 'message': 'Failed to connect to the remote server'})
        
        # Get the path to the audit script
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'system_audit.sh')
        
        # Upload the script to the remote server
        remote_script_path = remote_manager.upload_script(script_path)
        if not remote_script_path:
            remote_manager.disconnect()
            return jsonify({'success': False, 'message': 'Failed to upload audit script to remote server'})
        
        # Run the audit on the remote server
        stdout, stderr, exit_code = remote_manager.run_audit(remote_script_path)
        
        if exit_code != 0:
            remote_manager.disconnect()
            return jsonify({
                'success': False, 
                'message': 'Remote audit failed', 
                'error': stderr
            })
        
        # Fetch the report from the remote server
        report_pattern = r'system_audit_report_\d{8}_\d{6}\.txt'
        local_report_path, report_content = remote_manager.fetch_report(report_pattern)
        
        if not local_report_path or not report_content:
            remote_manager.disconnect()
            return jsonify({'success': False, 'message': 'Failed to fetch audit report from remote server'})
        
        # Clean up remote files
        remote_manager.cleanup(remote_script_path)
        
        # Disconnect from the remote server
        remote_manager.disconnect()
        
        # Store the report file path in the session for email sending
        session['latest_report'] = local_report_path
        
        # Generate AI summary and recommendations
        analysis = analyzer.analyze_report(report_content)
        ai_summary_html = analyzer.format_analysis_html(analysis)
        
        # Store the AI summary in the session for email sending
        session['ai_summary'] = analysis
        session['ai_summary_html'] = ai_summary_html
        
        # Store remote server info in session
        session['remote_audit'] = {
            'hostname': hostname,
            'username': username
        }
        
        return jsonify({
            'success': True,
            'message': 'Remote audit completed successfully',
            'report': report_content,
            'report_file': local_report_path,
            'ai_summary': ai_summary_html
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'An error occurred during remote audit: {str(e)}'
        })

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

