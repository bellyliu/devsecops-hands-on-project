# AWS WAF Managed Rule Groups - Baseline Protection Summary

A comprehensive guide to AWS WAF's baseline managed rule groups that provide foundational web application security protection against common threats and vulnerabilities.

## 📋 Overview

AWS WAF baseline managed rule groups provide **general protection against a wide variety of common threats**. These rule groups are designed to establish foundational security for web applications and should be considered for any AWS WAF implementation.

### 🎯 Key Benefits

- ✅ **OWASP Top 10 Protection** - Covers high-risk vulnerabilities from OWASP publications
- 🔍 **Comprehensive Coverage** - Protects against exploitation of common vulnerabilities
- 🏷️ **Request Labeling** - Adds labels for CloudWatch metrics and downstream processing
- 🛡️ **Ready-to-Use** - Pre-configured rules requiring minimal setup
- 📊 **CloudWatch Integration** - Automatic metrics and monitoring

---

## 🛡️ Baseline Rule Groups

### 1. Core Rule Set (CRS) Managed Rule Group

**Primary baseline protection for all web applications**

- **Vendor Name**: `AWS`
- **Rule Group Name**: `AWSManagedRulesCommonRuleSet`
- **WCU (Web ACL Capacity Units)**: `700`
- **Recommendation**: Consider using for **any AWS WAF use case**

#### 🔐 Protection Categories

| Category                  | Description                                                     | Rule Count |
| ------------------------- | --------------------------------------------------------------- | ---------- |
| **User Agent Validation** | Blocks missing or suspicious User-Agent headers                 | 2 rules    |
| **Size Restrictions**     | Prevents oversized requests (query strings, cookies, body, URI) | 4 rules    |
| **SSRF Protection**       | Blocks EC2 metadata exfiltration attempts                       | 4 rules    |
| **File Inclusion**        | Prevents Local File Inclusion (LFI) attacks                     | 3 rules    |
| **Remote File Inclusion** | Blocks RFI attacks with IPv4 URLs                               | 3 rules    |
| **Cross-Site Scripting**  | XSS protection across all request components                    | 4 rules    |
| **Restricted Extensions** | Blocks unsafe file extensions (.log, .ini)                      | 2 rules    |

#### 📏 Size Limits Enforced

- **Query String**: Max 2,048 bytes
- **Cookie Header**: Max 10,240 bytes
- **Request Body**: Max 8 KB (8,192 bytes)
- **URI Path**: Max 1,024 bytes

#### 🚨 Key Rules Details

**User Agent Protection:**

- `NoUserAgent_HEADER` - Blocks requests missing User-Agent
- `UserAgent_BadBots_HEADER` - Blocks known bad bots (nessus, nmap, etc.)

**SSRF Prevention:**

- `EC2MetaDataSSRF_*` - Protects against AWS metadata service exploitation
- Inspects body, cookies, URI path, and query arguments

**XSS Protection:**

- `CrossSiteScripting_*` - Uses built-in AWS WAF XSS detection
- Example blocked: `<script>alert("hello")</script>`

**File Inclusion Prevention:**

- `GenericLFI_*` - Blocks path traversal (`../../` patterns)
- `GenericRFI_*` - Blocks remote file inclusion with IP addresses

---

### 2. Admin Protection Managed Rule Group

**Blocks external access to administrative interfaces**

- **Vendor Name**: `AWS`
- **Rule Group Name**: `AWSManagedRulesAdminProtectionRuleSet`
- **WCU**: `100`
- **Use Case**: Third-party software or administrative interface protection

#### 🔒 Protection Features

- **Admin Path Blocking**: Prevents access to administrative URLs
- **Example Patterns**: `sqlmanager`, admin panels, configuration interfaces
- **Risk Reduction**: Minimizes malicious administrative access attempts

#### 📋 Rules

| Rule Name                 | Description                     | Action |
| ------------------------- | ------------------------------- | ------ |
| `AdminProtection_URIPATH` | Blocks admin-reserved URI paths | Block  |

---

### 3. Known Bad Inputs Managed Rule Group

**Blocks known malicious request patterns and vulnerability exploits**

- **Vendor Name**: `AWS`
- **Rule Group Name**: `AWSManagedRulesKnownBadInputsRuleSet`
- **WCU**: `200`
- **Purpose**: Prevent exploitation and vulnerability discovery

#### 🎯 Threat Categories

**Java Deserialization RCE:**

- Protects against Spring Core/Cloud Function vulnerabilities
- CVEs: CVE-2022-22963, CVE-2022-22965
- Pattern example: `(java.lang.Runtime).getRuntime().exec("whoami")`

**Log4j Vulnerability Protection:**

- Comprehensive Log4j RCE protection
- CVEs: CVE-2021-44228, CVE-2021-45046, CVE-2021-45105
- Pattern example: `${jndi:ldap://example.com/}`

**General Bad Inputs:**

- `Host_localhost_HEADER` - Blocks localhost targeting
- `PROPFIND_METHOD` - Blocks suspicious HTTP methods
- `ExploitablePaths_URIPATH` - Prevents access to dangerous paths

#### 📊 Rules Breakdown

| Protection Type | Rule Count | Inspects                         |
| --------------- | ---------- | -------------------------------- |
| **Java RCE**    | 4 rules    | Headers, Body, URI, Query String |
| **Log4j RCE**   | 4 rules    | Headers, Body, URI, Query String |
| **Bad Inputs**  | 3 rules    | Headers, Methods, Paths          |

---

## 🔧 Implementation Guidelines

### 📋 Recommended Baseline Configuration

```
Core Rule Set (CRS) ──────────── Essential for all applications
     +
Admin Protection ──────────────── If using admin interfaces
     +
Known Bad Inputs ──────────────── Highly recommended for security
```

### 🏗️ Dev Environment Implementation Experience

**Baseline Protection Deployed:**

- ✅ Successfully implemented in development environment
- ✅ All three baseline rule groups activated and operational
- ✅ Monitoring and logging configured for rule evaluation

**Key Learnings from Dev Implementation:**

1. **Managed Rules are Immutable** - Cannot customize rule parameters
2. **Action Overrides Work Well** - Easy to switch from BLOCK to COUNT for testing
3. **Custom Rules Required** - Needed for application-specific exceptions
4. **Rule Ordering Matters** - Custom exceptions must be placed strategically

### 💡 Best Practices

1. **Start with Core Rule Set**

   - Essential foundation for any web application
   - Covers OWASP Top 10 and common vulnerabilities

2. **Add Admin Protection**

   - Use when running third-party software
   - Essential for applications with admin interfaces

3. **Include Known Bad Inputs**

   - Provides protection against latest CVEs
   - Minimal performance impact with high security value

4. **Monitor and Tune**
   - Review CloudWatch metrics regularly
   - Adjust rule actions based on false positives
   - Use labels for custom monitoring

### 🎯 Common Implementation Scenarios

**Scenario 1: Mobile App with Large Request Bodies**

- **Problem**: `SizeRestrictions_BODY` blocks file uploads >8KB
- **Solution**: Create custom rule to ALLOW large bodies for `/api/upload/*` paths
- **Implementation**: Place custom ALLOW rule before Core Rule Set

**Scenario 2: Monitoring Tools Blocked by User-Agent Rules**

- **Problem**: `UserAgent_BadBots_HEADER` blocks legitimate monitoring (e.g., Datadog, New Relic)
- **Solution**: Create custom rule to ALLOW specific trusted User-Agent patterns
- **Implementation**: Whitelist known monitoring tool user agents

**Scenario 3: API Endpoints Requiring Specific Headers**

- **Problem**: Admin protection blocks legitimate admin API calls
- **Solution**: Override `AdminProtection_URIPATH` to COUNT mode and create custom logic
- **Implementation**: Use IP-based restrictions with custom rules instead

### ⚠️ Important Considerations

**🚫 Managed Rules Limitations:**

- **Cannot Modify Rules**: AWS Managed Rules are read-only and cannot be customized
  - ❌ Cannot increase `SizeRestrictions_BODY` limits beyond default thresholds
  - ❌ Cannot update `UserAgent_BadBots_HEADER` patterns or whitelist specific user agents
  - ❌ Cannot modify any rule logic, patterns, detection criteria, or thresholds
  - ❌ Cannot add exceptions directly to managed rules

**✅ Action Override Options:**
You can only override the default BLOCK action to:

- `COUNT` - Log matches without blocking (ideal for testing/monitoring)
- `ALLOW` - Allow requests that match the rule (bypass the rule)
- `CAPTCHA` - Present CAPTCHA challenge to users before allowing access
- `CHALLENGE` - Present JavaScript challenge to verify legitimate clients

**📝 Custom Rules for Application-Specific Requirements:**
When managed rules are too restrictive, create custom rules to:

- **Allow Specific User-Agents**: Whitelist legitimate bots, monitoring tools, or internal applications
- **Permit Larger Request Bodies**: Support file uploads or API endpoints requiring >8KB payloads
- **Whitelist IP Ranges**: Allow trusted sources (office IPs, CDN origins, partner systems)
- **Create Targeted Exceptions**: Use specific conditions (path, headers, query parameters)

**🔄 Rule Ordering Strategy:**

1. Place custom **ALLOW** rules BEFORE managed rule groups in your Web ACL
2. Custom rules should be as specific as possible to minimize security gaps
3. Use rule labels to track custom exception usage

**Body Size Limits:**

- **ALB/AppSync**: Fixed 8 KB limit
- **CloudFront/API Gateway/Cognito**: 16 KB default (up to 64 KB configurable)
- **Oversize Handling**: Rules use "Continue" option

**Header Inspection Limits:**

- **Headers**: First 8 KB or 200 headers (whichever reached first)
- **Oversize Handling**: Uses "Continue" option

**Rule Versioning:**

- AWS regularly updates managed rules
- Check [AWS Managed Rules changelog](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-changelog.html)
- Use `DescribeManagedRuleGroup` API for version details

---

## 📊 Capacity Planning

| Rule Group           | WCU Required  | Recommended Use     |
| -------------------- | ------------- | ------------------- |
| **Core Rule Set**    | 700           | All applications    |
| **Admin Protection** | 100           | Admin interfaces    |
| **Known Bad Inputs** | 200           | All applications    |
| **Total Baseline**   | **1,000 WCU** | Complete protection |

---

## 🏷️ Labeling and Monitoring

### CloudWatch Labels

All baseline rule groups add labels to web requests:

- Format: `awswaf:managed:aws:{rule-group}:{rule-name}`
- Available for downstream rules and metrics
- Enables detailed monitoring and alerting

### Example Labels:

- `awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body`
- `awswaf:managed:aws:admin-protection:AdminProtection_URIPath`
- `awswaf:managed:aws:known-bad-inputs:Log4JRCE_Header`

---

## 🔗 Additional Resources

- **[AWS WAF Developer Guide](https://docs.aws.amazon.com/waf/latest/developerguide/)**
- **[AWS Managed Rules Changelog](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-changelog.html)**
- **[Web Request Labeling Documentation](https://docs.aws.amazon.com/waf/latest/developerguide/waf-labels.html)**
- **[CloudWatch Metrics for WAF](https://docs.aws.amazon.com/waf/latest/developerguide/waf-metrics.html)**
- **[OWASP Top 10](https://owasp.org/www-project-top-ten/)**

---

## 🚀 Quick Start

### 🏃‍♂️ Rapid Deployment (Proven in Dev Environment)

1. **Enable Core Rule Set** for baseline OWASP protection

   - Start with COUNT mode to assess impact
   - Switch to BLOCK after validating no false positives

2. **Add Known Bad Inputs** for CVE protection

   - Generally safe to deploy in BLOCK mode immediately
   - Minimal false positives for most applications

3. **Include Admin Protection** if applicable

   - Test thoroughly with legitimate admin access patterns
   - Consider COUNT mode initially for admin endpoints

4. **Create Custom Exception Rules**

   - Identify application-specific requirements early
   - Document all custom exceptions for security review

5. **Monitor and Iterate**
   - Use CloudWatch metrics for ongoing tuning
   - Review WAF logs regularly for blocked legitimate traffic
   - Maintain documentation of all customizations

### ⚡ Development Environment Tips

- **Start Conservative**: Begin with COUNT actions, then gradually enable BLOCK
- **Test Thoroughly**: Validate all application flows before production deployment
- **Document Exceptions**: Keep detailed records of custom rules and their justifications
- **Plan for Scale**: Consider WCU capacity for production environments (1,000+ WCU baseline)

> **Note**: This summary is based on the most recent static version. Always check the AWS documentation for the latest updates and version information.
