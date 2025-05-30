# API template for user/roles/api_keys

## Setup:
### Create `.env` file
```bash
cat > .env <<'EOF'
MONGO_URI="localhost:27017"
MONGODB_ROOT_USER="admin"
MONGODB_ROOT_PASSWORD="admin"
REDIS_URL="redis://localhost:6379"
EXTERNAL_URL="http://localhost:8000"
PORT="8000"
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