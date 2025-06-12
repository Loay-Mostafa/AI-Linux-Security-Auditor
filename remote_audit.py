import paramiko
import os
import tempfile
import time
import re

class RemoteAuditManager:
    """
    A class to handle remote system audits via SSH.
    """
    
    def __init__(self):
        """Initialize the RemoteAuditManager."""
        self.ssh_client = None
        self.sftp_client = None
    
    def connect(self, hostname, username, password=None, key_path=None, port=22):
        """
        Connect to a remote host via SSH.
        
        Args:
            hostname (str): The hostname or IP address of the remote server
            username (str): The SSH username
            password (str, optional): The SSH password (if using password auth)
            key_path (str, optional): Path to private key file (if using key-based auth)
            port (int, optional): SSH port, defaults to 22
            
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_kwargs = {
                'hostname': hostname,
                'username': username,
                'port': port,
                'timeout': 10
            }
            
            # Use either password or key-based authentication
            if password:
                connect_kwargs['password'] = password
            elif key_path:
                connect_kwargs['key_filename'] = key_path
            else:
                raise ValueError("Either password or key_path must be provided")
            
            self.ssh_client.connect(**connect_kwargs)
            self.sftp_client = self.ssh_client.open_sftp()
            return True
            
        except Exception as e:
            print(f"SSH connection error: {str(e)}")
            self.disconnect()
            return False
    
    def disconnect(self):
        """Close SSH and SFTP connections."""
        if self.sftp_client:
            self.sftp_client.close()
            self.sftp_client = None
            
        if self.ssh_client:
            self.ssh_client.close()
            self.ssh_client = None
    
    def upload_script(self, local_script_path):
        """
        Upload the audit script to the remote server.
        
        Args:
            local_script_path (str): Path to the local audit script
            
        Returns:
            str: Path to the uploaded script on the remote server, or None if failed
        """
        if not self.sftp_client:
            return None
            
        try:
            # Create a temporary file on the remote server
            remote_path = f"/tmp/system_audit_{int(time.time())}.sh"
            
            # Upload the script
            self.sftp_client.put(local_script_path, remote_path)
            
            # Make the script executable
            self.ssh_client.exec_command(f"chmod +x {remote_path}")
            
            return remote_path
            
        except Exception as e:
            print(f"Error uploading script: {str(e)}")
            return None
    
    def run_audit(self, remote_script_path):
        """
        Run the audit script on the remote server.
        
        Args:
            remote_script_path (str): Path to the script on the remote server
            
        Returns:
            tuple: (stdout, stderr, exit_code) from the remote command
        """
        if not self.ssh_client:
            return None, "Not connected to remote server", 1
            
        try:
            # Run the script with sudo
            # Note: This assumes the user has sudo privileges without password
            # In a real environment, you might need to handle sudo password differently
            stdin, stdout, stderr = self.ssh_client.exec_command(f"sudo {remote_script_path}")
            
            # Wait for the command to complete
            exit_code = stdout.channel.recv_exit_status()
            
            # Read output
            stdout_str = stdout.read().decode('utf-8')
            stderr_str = stderr.read().decode('utf-8')
            
            return stdout_str, stderr_str, exit_code
            
        except Exception as e:
            print(f"Error running remote audit: {str(e)}")
            return None, str(e), 1
    
    def fetch_report(self, remote_report_pattern):
        """
        Fetch the generated report file from the remote server.
        
        Args:
            remote_report_pattern (str): Pattern to match the report file name
            
        Returns:
            tuple: (local_path, report_content) or (None, None) if failed
        """
        if not self.ssh_client or not self.sftp_client:
            return None, None
            
        try:
            # List files in the current directory on the remote server
            stdin, stdout, stderr = self.ssh_client.exec_command("ls -t")
            file_list = stdout.read().decode('utf-8').splitlines()
            
            # Find the most recent report file
            report_file = None
            for file in file_list:
                if re.match(remote_report_pattern, file):
                    report_file = file
                    break
            
            if not report_file:
                return None, None
            
            # Create a local temporary file to store the report
            local_file = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
            local_path = local_file.name
            local_file.close()
            
            # Download the report
            self.sftp_client.get(report_file, local_path)
            
            # Read the report content
            with open(local_path, 'r') as f:
                report_content = f.read()
            
            return local_path, report_content
            
        except Exception as e:
            print(f"Error fetching report: {str(e)}")
            return None, None
    
    def cleanup(self, remote_script_path):
        """
        Clean up temporary files on the remote server.
        
        Args:
            remote_script_path (str): Path to the script on the remote server
        """
        if not self.ssh_client:
            return
            
        try:
            self.ssh_client.exec_command(f"rm -f {remote_script_path}")
        except Exception as e:
            print(f"Error during cleanup: {str(e)}")
