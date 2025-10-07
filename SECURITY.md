# GreyNoise MCP Server Security Documentation

## Overview

The GreyNoise MCP Server is a client-side tool that runs locally within Claude Desktop (or compatible MCP hosts) on the end user's machine. This document outlines the security model, deployment considerations, and our security practices.

## Deployment Model

### Client-Side Architecture

**Critical Understanding:** This MCP server runs entirely on the user's local machine. GreyNoise does not host, operate, or have access to any MCP server instances.

- **Execution Environment**: Runs within Claude Desktop or other MCP-compatible hosts
- **Network Boundary**: Makes HTTPS requests directly from user's machine to GreyNoise API
- **Credential Storage**: API keys are managed by the user in their local MCP configuration
- **No Server-Side Components**: There is no GreyNoise-operated infrastructure for this MCP server

### Security Responsibility Model

```
┌──────────────────────────────────────────────────┐
│ Your Responsibility                              │
│ • Secure deployment environment                  │
│ • API key management and rotation                │
│ • Network policies and egress filtering          │
│ • Local system security                          │
│ • MCP server configuration                       │
└──────────────────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────┐
│ GreyNoise Responsibility                         │
│ • API infrastructure security (SOC2 Type II)     │
│ • MCP server code quality and maintenance        │
│ • Dependency vulnerability management            │
│ • Responsible disclosure handling                │
└──────────────────────────────────────────────────┘
```

## What This MCP Server Does (and Doesn't Do)

### ✅ Does

- Makes authenticated HTTPS requests to `api.greynoise.io`
- Processes API responses and formats them for Claude
- Implements standard MCP protocol for tool invocation
- Uses your provided API key for authentication

### ❌ Does NOT

- Execute shell commands or system processes
- Access your file system (beyond standard MCP protocol requirements)
- Store or transmit your API key anywhere except to GreyNoise API
- Make requests to any domains other than GreyNoise
- Maintain persistent state or logging beyond standard MCP operations
- Require elevated privileges or system access

## Code Security

### Supply Chain Security

We maintain multiple layers of defense for our dependencies:

- **npm audit**: Run on every build; critical vulnerabilities are addressed immediately
- **GitHub Dependabot**: Automated dependency updates and vulnerability alerts
- **SonarQube**: Static code analysis on all commits
- **Dependency Pinning**: Exact versions specified in package-lock.json

### Code Quality

- **Open Source**: Full source code available for audit at [repository URL]
- **No Obfuscation**: All code is human-readable JavaScript/TypeScript
- **Minimal Dependencies**: Limited dependency tree reduces attack surface
- **TypeScript**: Type safety reduces entire classes of runtime errors

### Vulnerability Response

We follow responsible disclosure practices:

- **Security Issues**: Report to security@greynoise.io
- **Response Time**: Initial response within 48 hours
- **Disclosure**: CVE assignments for confirmed vulnerabilities
- **Updates**: Security patches released via npm and GitHub releases

## API Security

### GreyNoise API Infrastructure

- **SOC2 Type II Certified**: Annual audits of security controls
- **TLS 1.2+**: All API communications encrypted in transit
- **API Key Authentication**: Bearer token authentication required
- **Rate Limiting**: API-level rate limits prevent abuse
- **No PII Storage**: We don't collect personally identifiable information through this MCP server

### API Key Handling

The MCP server requires your GreyNoise API key to function. Here's how it's handled:

```json
{
  "mcpServers": {
    "greynoise": {
      "command": "npx",
      "args": ["-y", "@greynoise/mcp-server"],
      "env": {
        "GREYNOISE_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

**Security Notes:**

- API keys are passed via environment variables (not command-line arguments)
- Keys are never logged or written to disk by the MCP server
- Keys are only transmitted to `api.greynoise.io` via HTTPS
- Treat your API key like a password and rotate it if compromised

## Deployment Best Practices

### For Individual Users

1. **Obtain API Key Securely**: Get your key from the GreyNoise web console
2. **Configure Claude Desktop**: Add the MCP server to your Claude config file
3. **Verify Configuration**: Ensure the API key is in your environment/config, not hardcoded
4. **Monitor Usage**: Check your GreyNoise dashboard for unexpected API usage

### For Enterprise Deployments

#### Network Security

- **Egress Filtering**: Allow HTTPS to `api.greynoise.io` only
- **Proxy Support**: Set standard HTTP proxy environment variables if required
- **Certificate Pinning**: Consider TLS inspection policies for your environment

#### API Key Management

- **Rotation Policy**: Implement regular API key rotation
- **Least Privilege**: Use API keys with minimum required permissions
- **Monitoring**: Track API usage via GreyNoise dashboard
- **Revocation**: Immediately revoke keys if compromise suspected

#### Deployment Control

- **Package Verification**: Verify npm package signatures and checksums
- **Version Pinning**: Pin to specific versions in production
- **Change Management**: Test updates in non-production before deployment
- **Code Audit**: Review source code before deploying to sensitive environments

#### Configuration Management

```json
// Example: Secure configuration with environment variables
{
  "mcpServers": {
    "greynoise": {
      "command": "npx",
      "args": ["-y", "@greynoise/mcp-server"],
      "env": {
        "GREYNOISE_API_KEY": "${GREYNOISE_API_KEY}",
        "NODE_ENV": "production"
      }
    }
  }
}
```

## Compliance Considerations

### Data Flow

```
Claude Desktop (Your Machine)
    ↓
MCP Server (Your Machine)
    ↓
HTTPS Request
    ↓
api.greynoise.io (GreyNoise SOC2 Infrastructure)
    ↓
HTTPS Response
    ↓
MCP Server (Your Machine)
    ↓
Claude Desktop (Your Machine)
```

### Data Handling

- **No Data Retention**: MCP server doesn't persist any data locally
- **No Logging**: API keys and query data are not logged
- **Ephemeral**: Data exists only in memory during request/response cycle
- **No Third-Party Sharing**: Data only flows between your machine and GreyNoise API

### Compliance Frameworks

If you need to evaluate this MCP server against compliance frameworks:

- **SOC2**: GreyNoise API is SOC2 Type II certified; MCP server is client software
- **GDPR**: No personal data is processed by the MCP server itself
- **HIPAA**: Client-side tool; your deployment controls data handling
- **ISO 27001**: Follows secure development practices

## Security Auditing

### For Your Security Team

You should audit:

1. **Source Code Review**: Clone the repository and review all code
2. **Dependency Analysis**: Run `npm audit` and review `package-lock.json`
3. **Network Behavior**: Monitor outbound connections (should only be to GreyNoise API)
4. **Permission Requirements**: Verify no elevated privileges required
5. **Configuration Security**: Ensure API keys are properly secured

### Audit Commands

```bash
# Clone and inspect
git clone [repository-url]
cd greynoise-mcp-server

# Check dependencies
npm audit
npm ls

# Review source
cat src/index.ts  # or wherever main code lives

# Build and inspect
npm run build
```

## Known Limitations

- **Local Environment Security**: We cannot control the security of the environment where you deploy this
- **API Key Protection**: Users are responsible for securing their own API keys
- **Network Security**: Depends on the security of your local network and DNS
- **MCP Protocol Security**: Subject to security model of Claude Desktop / MCP host

## Reporting Security Issues

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, email us at: **security@greynoise.io**

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested remediation (if any)

We will respond within 48 hours and work with you on coordinated disclosure.

## Security Resources

- **GreyNoise Security**: https://www.greynoise.io/security
- **API Documentation**: https://docs.greynoise.io
- **SOC2 Report**: Available for enterprise customers
- **MCP Protocol Spec**: https://modelcontextprotocol.io

## Updates and Notifications

- **Security Advisories**: Published via GitHub Security Advisories
- **npm Updates**: Security patches released immediately via npm
- **Changelog**: All changes documented in NEWS.md
- **Breaking Changes**: Communicated via major version bumps

---

**Last Updated**: 2025-10-07
**Version**: 0.1.0  
**Maintained By**: GreyNoise Labs Team
