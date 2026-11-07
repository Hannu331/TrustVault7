# TrustVault – Threat Model

## 1. Introduction

TrustVault is a document management application that handles user accounts, uploaded documents, document permissions, version history, and PDF modifications.

This document identifies potential security threats, their possible impact, and recommended mitigation measures.

## 2. Assets to Protect

The following assets require protection:

- Usernames and password hashes.
- User session information.
- Uploaded documents.
- Document metadata.
- Document versions.
- User permissions and access records.
- Audit logs.
- Database files and application configuration.

## 3. Potential Security Threats

### 3.1 Unauthorized Access

**Threat:** An unauthorized user may attempt to access documents or restricted application features.

**Impact:** Confidential documents may be exposed or modified.

**Mitigation:**
- Require authentication for protected routes.
- Enforce role-based access control.
- Verify document-level permissions.
- Deny access when authorization checks fail.

### 3.2 Weak Authentication

**Threat:** Weak passwords or compromised user credentials may allow attackers to access accounts.

**Impact:** Unauthorized access to user accounts and documents.

**Mitigation:**
- Store passwords using secure password hashing.
- Enforce appropriate password requirements.
- Protect login sessions.
- Implement login rate limiting.

### 3.3 Malicious File Uploads

**Threat:** Attackers may upload malicious or disguised files.

**Impact:** Malicious content could affect the application or its users.

**Mitigation:**
- Allow only approved file formats.
- Enforce upload size restrictions.
- Generate unique server-side filenames.
- Validate file contents, not just file extensions.
- Consider malware scanning.

### 3.4 Session Hijacking

**Threat:** An attacker may steal or misuse an authenticated user's session.

**Impact:** The attacker could impersonate the user.

**Mitigation:**
- Use secure session configuration.
- Enable HTTPS in production.
- Configure HttpOnly and Secure cookie attributes.
- Apply appropriate session expiration.
- Regenerate sessions after authentication.

### 3.5 Insecure Document Sharing

**Threat:** Incorrect permission checks may allow users to access documents that were not shared with them.

**Impact:** Unauthorized disclosure or modification of documents.

**Mitigation:**
- Verify permissions on every protected document operation.
- Apply least-privilege access.
- Validate ownership and sharing permissions.
- Test access control using multiple user accounts.

### 3.6 SQL Injection

**Threat:** Attackers may attempt to manipulate database queries using malicious input.

**Impact:** Unauthorized data access, modification, or deletion.

**Mitigation:**
- Use parameterized SQL queries.
- Avoid constructing SQL statements by directly concatenating user input.
- Validate user-supplied values.

### 3.7 Cross-Site Scripting (XSS)

**Threat:** Malicious scripts may be injected into document metadata or user-controlled content.

**Impact:** Scripts could execute in another user's browser.

**Mitigation:**
- Escape user-generated content before displaying it.
- Sanitize untrusted HTML where applicable.
- Apply an appropriate Content Security Policy.
- Avoid unsafe JavaScript DOM operations.

### 3.8 Cross-Site Request Forgery (CSRF)

**Threat:** An attacker may trick an authenticated user into submitting an unwanted request.

**Impact:** Unauthorized document changes or account actions.

**Mitigation:**
- Use CSRF tokens for state-changing form submissions.
- Validate request origins where appropriate.
- Configure SameSite cookie settings.
- Avoid state-changing GET endpoints.

### 3.9 Sensitive Data Exposure

**Threat:** Database files, uploaded documents, credentials, or configuration values may be exposed.

**Impact:** Confidential information could be disclosed.

**Mitigation:**
- Restrict access to database and upload directories.
- Never commit secrets or real user data to public repositories.
- Use environment variables for sensitive configuration.
- Apply encryption in transit and at rest where required.
- Restrict production file permissions.

### 3.10 Denial of Service (DoS)

**Threat:** Attackers may send excessive requests or upload large numbers of files.

**Impact:** The application may become unavailable or consume excessive resources.

**Mitigation:**
- Enforce file size limits.
- Apply request rate limiting.
- Set appropriate request timeouts.
- Monitor resource consumption.
- Restrict upload frequency where necessary.

## 4. Security Priorities

| Priority | Security Area |
|---|---|
| Critical | Authentication and authorization |
| High | File upload validation |
| High | Session protection |
| High | Document access control |
| High | Sensitive data protection |
| Medium | SQL injection prevention |
| Medium | XSS and CSRF protection |
| Medium | Denial-of-service prevention |

## 5. Security Testing Checklist

- [ ] Verify that unauthenticated users cannot access protected routes.
- [ ] Verify that users cannot access unauthorized documents.
- [ ] Test upload restrictions and file size limits.
- [ ] Test document ownership and sharing permissions.
- [ ] Verify password hashes are stored instead of plaintext passwords.
- [ ] Test session expiration and logout behavior.
- [ ] Check that database files and secrets are not publicly exposed.
- [ ] Test inputs for SQL injection and XSS vulnerabilities.
- [ ] Verify CSRF protection for state-changing operations.
- [ ] Test application behavior under excessive requests.

## 6. Conclusion

TrustVault requires a layered security approach to protect user accounts, documents, and application data. Authentication, authorization, secure file handling, session protection, and regular security testing are essential for reducing security risks.

**Important:** This document describes potential threats and recommended controls. It does not certify that every listed security control is currently implemented or tested in TrustVault.