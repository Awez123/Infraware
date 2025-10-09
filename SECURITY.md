# Security Policy

## Supported Versions

We actively support the following versions of InfraWare:

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| 1.x.x   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in InfraWare, please report it responsibly.

### How to Report

1. **DO NOT** create a public GitHub issue for security vulnerabilities
2. Email us directly at: **security@infraware.dev**
3. Include the following information:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: We'll acknowledge receipt within 24 hours
- **Investigation**: We'll investigate and assess the vulnerability within 5 business days
- **Resolution**: We'll work on a fix and coordinate disclosure timing with you
- **Credit**: We'll credit you in our security advisory (unless you prefer to remain anonymous)

### Security Best Practices

When using InfraWare:

1. **Keep Updated**: Always use the latest version
2. **Secure Environment**: Run InfraWare in secure environments
3. **API Keys**: Protect your cloud provider API keys
4. **Custom Rules**: Review custom security rules before deployment
5. **Database Security**: Secure your CVE database files

### Known Security Considerations

- InfraWare processes infrastructure files that may contain sensitive information
- CVE database contains vulnerability information that should be handled securely
- Cost analysis may require cloud provider credentials

### Security Features

InfraWare includes several security features:

- **No Data Persistence**: Scan results are not stored by default
- **Local Processing**: Most operations run locally
- **Secure APIs**: External API calls use HTTPS
- **Input Validation**: All inputs are validated and sanitized

## Contact

For security-related questions or concerns:
- Email: security@infraware.dev
- PGP Key: Available on request

Thank you for helping keep InfraWare secure!