# Contributing to DetectiveSloth (Automated Threat Hunt Generator)

Thank you for your interest in contributing to DetectiveSloth! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Areas of Contribution](#areas-of-contribution)

## Getting Started

Before contributing, please:

1. Read the [README.md](README.md) to understand the project
2. Review the [QUICKSTART.md](QUICKSTART.md) to set up your development environment
3. Check existing [issues](../../issues) and [pull requests](../../pulls)
4. Join discussions in issues to understand ongoing work

## Development Setup

### Prerequisites

- Python 3.11 or higher
- Node.js 18 or higher
- PostgreSQL (or use SQLite for development)
- Git
- Docker (optional, for containerized development)

### Backend Setup

```bash
cd backend

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env as needed

# Initialize database
python scripts/init_db.py
```

### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Configure environment
cp .env.example .env

# Start development server
npm run dev
```

### Running with Docker

```bash
docker-compose up --build
```

## How to Contribute

### Reporting Bugs

When reporting bugs, please include:

- Clear description of the issue
- Steps to reproduce
- Expected vs. actual behavior
- Environment details (OS, Python version, etc.)
- Relevant logs or error messages

### Suggesting Features

For feature requests, please:

- Check if the feature already exists or is planned
- Clearly describe the use case
- Explain how it benefits threat hunters
- Provide examples if applicable

### Submitting Changes

1. **Fork the repository** and create a feature branch
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following our coding standards

3. **Test your changes** thoroughly

4. **Commit your changes** with clear messages
   ```bash
   git commit -m "Add feature: description of what you did"
   ```

5. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Open a Pull Request** with:
   - Clear title and description
   - Reference to related issues
   - Screenshots (for UI changes)
   - Testing notes

## Coding Standards

### Python (Backend)

- Follow PEP 8 style guide
- Use type hints for function parameters and return values
- Write docstrings for all functions and classes
- Keep functions focused and modular
- Use meaningful variable names

**Format your code:**
```bash
black app/
flake8 app/
mypy app/
```

### TypeScript/React (Frontend)

- Follow ESLint configuration
- Use TypeScript for type safety
- Write functional components with hooks
- Keep components small and reusable
- Use meaningful component and variable names

**Lint your code:**
```bash
npm run lint
```

### General Guidelines

- Write self-documenting code
- Add comments for complex logic
- Keep functions under 50 lines when possible
- Avoid duplication (DRY principle)
- Handle errors gracefully
- Never commit sensitive data (API keys, credentials)

## Testing

### Backend Tests

```bash
cd backend
pytest tests/ -v
```

### Frontend Tests

```bash
cd frontend
npm run test
```

### Writing Tests

- Write unit tests for new functions
- Write integration tests for API endpoints
- Test edge cases and error conditions
- Aim for >80% code coverage

## Pull Request Process

1. **Before submitting:**
   - Ensure all tests pass
   - Update documentation if needed
   - Add your changes to relevant phase documentation
   - Run linters and fix any issues

2. **PR Description should include:**
   - Summary of changes
   - Motivation and context
   - Related issues (closes #123)
   - Testing performed
   - Screenshots (for UI changes)

3. **After submitting:**
   - Respond to review comments promptly
   - Make requested changes
   - Keep the PR up to date with main branch

4. **Merge criteria:**
   - At least one approving review
   - All tests passing
   - No merge conflicts
   - Documentation updated
   - Code follows project standards

## Areas of Contribution

### High Priority

1. **Query Templates**
   - Add templates for uncovered MITRE techniques
   - Improve existing templates
   - Add support for new EDR platforms
   - Reduce false positives

2. **Threat Intelligence**
   - Integrate new threat feeds
   - Improve IOC enrichment
   - Enhance TTP extraction algorithms
   - Add new threat actor playbooks

3. **Frontend Features**
   - Improve UI/UX
   - Add data visualizations
   - Enhance dashboard analytics
   - Mobile responsiveness

4. **Documentation**
   - Improve setup guides
   - Add use case examples
   - Create video tutorials
   - Translate documentation

### Medium Priority

5. **EDR Integration**
   - Implement actual API connectors
   - Add authentication flows
   - Improve error handling
   - Add result parsing

6. **Performance**
   - Optimize database queries
   - Improve query generation speed
   - Add caching strategies
   - Reduce API response times

7. **Testing**
   - Increase test coverage
   - Add integration tests
   - Add E2E tests for frontend
   - Performance testing

### Future Enhancements

8. **Machine Learning**
   - False positive prediction
   - Anomaly detection
   - Query optimization suggestions

9. **Automation**
   - Scheduled hunt campaigns
   - Automated reporting
   - Alert integration

10. **Collaboration**
    - Real-time updates (WebSocket)
    - Team chat integration
    - Advanced permission systems

## Code Review Process

All contributions go through code review:

- Reviews typically completed within 2-3 days
- Be open to feedback and suggestions
- Reviews ensure code quality and consistency
- Learn from feedback and apply to future PRs

## Community Guidelines

- Be respectful and professional
- Help other contributors
- Share knowledge and best practices
- Follow our Code of Conduct
- Ask questions if unclear

## Getting Help

If you need help:

- Check the [README.md](README.md) and [QUICKSTART.md](QUICKSTART.md)
- Search existing issues
- Create a new issue with your question
- Tag issues appropriately (bug, question, enhancement)

## Recognition

Contributors will be:

- Listed in project acknowledgments
- Mentioned in release notes
- Credited in relevant documentation

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to DetectiveSloth! Together, we're making threat hunting more accessible and effective. 🎯
