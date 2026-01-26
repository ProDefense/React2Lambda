# react2lambda

Exploit tool for CVE-2025-55182 (React2Shell) in Next.js Lambda deployments. Exploits Server Side JavaScript Injection (SSJI) via prototype pollution in React Server Components to exfiltrate AWS credentials and environment variables from serverless Lambda functions.

## Background

Traditional React2Shell scanners miss vulnerable serverless deployments. While Webpack bundling prevents traditional RCE (shell access), the vulnerability enables SSJI that can exfiltrate AWS credentials—often more dangerous than shell access in cloud environments.

For full research details, see: **[Expanding React2Shell for Serverless Lambda Functions](https://platformsecurity.com/blog/react2shell-for-lambdas)**

## Requirements

- Python 3.10+
- `requests` library

```bash
pip3 install requests
```

## Usage

```bash
react2lambda <host> -c <js:expression>
```

### Examples

```bash
# Check Node.js version
react2lambda https://target.com 'js:process.version'

# Dump environment variables (including AWS credentials)
react2lambda https://target.com 'js:process.env'

```

## How It Works

The tool exploits prototype pollution in Next.js Server Actions to inject JavaScript code that executes in the Lambda runtime. Output is extracted from redirect headers or error digests in the response.

AWS credentials in the output are automatically highlighted in red for visibility.

## Disclaimer

This tool is for authorized security testing and research purposes only. Only use against systems you own or have explicit permission to test.
