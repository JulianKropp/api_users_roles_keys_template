# API template for user/roles/api_keys

## Prerequisites
- Python 3.8+
- [uv](https://github.com/astral-sh/uv) (A fast Python package and project manager)
- Docker and Docker Compose

## Setup

### 1. Create `.env` file
```bash
cat > .env <<'EOF'
HOST="0.0.0.0"
PORT=8000
EXTERNAL_URL="http://localhost:8000"
REDIS_URL="redis://localhost:6379"
SESSION_DURATION_SECONDS=86400
WEBRTC_TIMEOUT=5
MONGO_URI="localhost:27017"
MONGO_USER="admin"
MONGO_PASSWORD="admin"
MONGO_DB_NAME="user_management"
EOF
```

### 2. Start MongoDB and Redis
```bash
docker compose up -d
```

### 3. Install dependencies and set up the environment
```bash
# Install uv if you haven't already
curl -sSf https://astral.sh/uv/install.sh | sh

# Create and activate virtual environment
uv venv
source .venv/bin/activate

# Install dependencies
uv pip install -e ".[dev]"  # For development with all dev dependencies
# or for production:
# uv pip install .
```

### 4. Run the application
```bash
uvicorn main:app --reload
```

### 5. Access the application
- API Docs (Swagger UI): [http://localhost:8000/docs](http://localhost:8000/docs)
- ReDoc: [http://localhost:8000/redoc](http://localhost:8000/redoc)
- Raw OpenAPI schema: [http://localhost:8000/openapi.json](http://localhost:8000/openapi.json)

## Development

### Running tests
```bash
pytest
```

### Type checking
```bash
mypy .
```

### Updating dependencies
Edit `pyproject.toml` and run:
```bash
uv pip install -e ".[dev]"
```