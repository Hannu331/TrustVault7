# TrustVault – AI Development Prompts

This document records the prompts and development instructions used to plan, implement, debug, and improve the TrustVault application.

## 1. Project Planning

**Prompt:**

Design a secure document management system named TrustVault. The application should support user authentication, document uploads, document management, sharing, version control, and PDF editing.

## 2. Backend Development

**Prompt:**

Develop a Python FastAPI backend for TrustVault. Organize the application into core configuration, routes, and service modules. Implement REST endpoints for authentication, document uploads, document retrieval, document updates, and downloads.

## 3. Database Integration

**Prompt:**

Design a database structure for TrustVault using SQLite. Include tables for users, documents, document versions, permissions, and audit logs. Maintain appropriate relationships between records.

## 4. Authentication

**Prompt:**

Implement user registration, login, and logout functionality using FastAPI sessions. Store password hashes instead of plaintext passwords and implement role-based access control.

## 5. Document Upload

**Prompt:**

Create a document upload feature that supports PDF, DOC, DOCX, TXT, and CSV files. Validate file extensions and file sizes, generate unique stored filenames, and save document metadata in the database.

## 6. Document Version Management

**Prompt:**

Implement document version management. Every successful document modification should create a new version while preserving the original document and maintaining modification history.

## 7. PDF Editing

**Prompt:**

Implement PDF editing functionality using PyMuPDF. Support adding text, comments, highlights, signatures, rectangles, drawings, and images. Save modifications as new document versions.

## 8. Document Access Control

**Prompt:**

Implement role-based and document-level access control. Verify user permissions before allowing document viewing, editing, uploading, sharing, or downloading.

## 9. Frontend Integration

**Prompt:**

Develop a responsive frontend for TrustVault using HTML, CSS, JavaScript, and Jinja2 templates. Integrate the frontend with FastAPI endpoints and provide interfaces for authentication, document management, uploading, previewing, and editing.

## 10. Debugging and Testing

**Prompt:**

Analyze the FastAPI application for errors involving authentication, session management, database connectivity, file uploads, permissions, and document processing. Identify the root cause and recommend fixes without bypassing security controls.

## Development Guidelines

- Follow modular application architecture.
- Keep database operations separate from route handlers where practical.
- Validate user input and uploaded files.
- Enforce authorization on protected operations.
- Handle exceptions appropriately.
- Avoid exposing passwords, session secrets, and sensitive information.
- Test important application workflows before deployment.

**Note:** These are representative development prompts documenting the intended workflows and implementation requirements. They are not a record of every exact prompt used during development.