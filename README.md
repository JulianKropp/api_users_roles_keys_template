# API template for user/roles/api_keys

## Setup:
### Create `.env` file
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

### Start MongoDB and Redis
```bash
docker compose up -d
```

### Install dependencies in a virtual environment
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Run the application
```bash
python3 main.py
```

### Done!
Open your browser and go to [http://localhost:8000/](http://localhost:8000/) and to [http://localhost:8000/docs#/](http://localhost:8000/docs#/) to see the API documentation.