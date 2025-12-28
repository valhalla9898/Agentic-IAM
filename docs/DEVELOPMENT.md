# Agentic-IAM - Development Guide

This guide covers setting up the development environment and contributing to Agentic-IAM.

## Prerequisites

- Python 3.9+
- Git
- PostgreSQL (optional, for production)
- Redis (optional, for caching)
- Docker & Docker Compose (optional)

## Development Setup

### 1. Clone Repository

```bash
git clone https://github.com/valhalla9898/Agentic-IAM.git
cd Agentic-IAM
```

### 2. Create Virtual Environment

```bash
# Using venv
python -m venv venv

# Activate (Linux/macOS)
source venv/bin/activate

# Activate (Windows)
venv\Scripts\activate
```

### 3. Install Development Dependencies

```bash
pip install -e ".[dev]"
```

### 4. Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your settings
# For development, defaults are usually fine
```

### 5. Initialize Database

```bash
# Create database
python -c "from database import init_db; init_db()"

# Run migrations (if applicable)
python scripts/migrate.py
```

## Running the Application

### Development Server

```bash
# Start API server
python -m uvicorn api.main:app --reload --port 8000

# In another terminal, start dashboard
streamlit run dashboard/components/agent_management.py
```

### With Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## Testing

### Run All Tests

```bash
pytest tests/ -v
```

### Run Specific Test Category

```bash
# Unit tests
pytest tests/test_unit/ -v

# Integration tests
pytest tests/test_integration/ -v

# API tests
pytest tests/ -v -m api

# With coverage report
pytest tests/ --cov=. --cov-report=html
```

### Run Performance Tests

```bash
python scripts/performance_test.py
```

## Code Quality

### Format Code

```bash
# Using black
black api/ core/ utils/ tests/

# Using autopep8
autopep8 --in-place --aggressive --recursive api/
```

### Linting

```bash
# Check with flake8
flake8 api/ core/ utils/ --max-line-length=120

# Check with pylint
pylint api/ core/ utils/
```

### Type Checking

```bash
mypy api/ core/ utils/ --ignore-missing-imports
```

### Security Check

```bash
# Run bandit
bandit -r api/ core/ utils/ -ll

# Check dependencies
safety check
```

## Project Structure

```
Agentic-IAM/
├── .github/
│   ├── workflows/          # GitHub Actions workflows
│   └── security/          # Security policies
├── api/                   # FastAPI application
│   ├── routers/          # API route handlers
│   ├── models.py         # Pydantic models
│   └── main.py           # FastAPI app setup
├── core/                 # Core IAM logic
│   └── agentic_iam.py   # Main IAM class
├── tests/                # Test suite
│   ├── test_unit/       # Unit tests
│   └── test_integration/ # Integration tests
├── scripts/             # Utility scripts
├── docs/                # Documentation
├── config/              # Configuration
├── utils/               # Utilities
└── requirements.txt     # Dependencies
```

## Contributing

### 1. Create Feature Branch

```bash
git checkout -b feature/your-feature-name
```

### 2. Make Changes

- Write code following project conventions
- Add tests for new functionality
- Update documentation

### 3. Commit Changes

```bash
git add .
git commit -m "feat: add new feature

- Description of changes
- What it does
- Why it's needed"
```

### 4. Push and Create PR

```bash
git push origin feature/your-feature-name
```

Create a pull request on GitHub with detailed description.

## Git Workflow

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Code style changes
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Test changes
- `chore`: Build/tooling changes

### Example

```
feat(auth): add JWT token validation

- Implement JWT token validation middleware
- Add support for token refresh
- Add tests for validation logic

Closes #123
```

## Debugging

### Debug API Server

```bash
# Start with debugging enabled
python -m pdb -m uvicorn api.main:app --reload

# Or use VSCode debugger with .vscode/launch.json
```

### Debug Tests

```bash
# Run specific test with debug output
pytest tests/test_unit/test_api/test_authentication.py -vv -s
```

### Check Logs

```bash
# API logs
tail -f logs/app.log

# Audit logs
tail -f logs/audit.log
```

## Releasing

### Version Bump

```bash
# Update version in pyproject.toml
# Then tag release
git tag v1.0.0
git push origin v1.0.0
```

### Build Distribution

```bash
python -m build
```

### Upload to PyPI

```bash
twine upload dist/*
```

## Additional Resources

- [API Documentation](./docs/api/API_REFERENCE.md)
- [Architecture Guide](./docs/ARCHITECTURE.md)
- [Security Guide](./docs/SECURITY.md)
- [README](./README.md)

## Support

For issues and questions:
- GitHub Issues: https://github.com/valhalla9898/Agentic-IAM/issues
- Discussions: https://github.com/valhalla9898/Agentic-IAM/discussions
- Email: team@agentic-iam.com
