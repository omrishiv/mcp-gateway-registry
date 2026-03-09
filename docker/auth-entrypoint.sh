#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.

echo "Starting Auth Server Setup..."

# --- DocumentDB CA Bundle Download ---
if [[ "${DOCUMENTDB_HOST}" == *"docdb-elastic.amazonaws.com"* ]]; then
    echo "Detected DocumentDB Elastic cluster"
    echo "Downloading DocumentDB Elastic CA bundle..."
    CA_BUNDLE_URL="https://www.amazontrust.com/repository/SFSRootCAG2.pem"
    CA_BUNDLE_PATH="/app/global-bundle.pem"
    if [ ! -f "$CA_BUNDLE_PATH" ]; then
        curl -fsSL "$CA_BUNDLE_URL" -o "$CA_BUNDLE_PATH"
        echo "DocumentDB Elastic CA bundle (SFSRootCAG2.pem) downloaded successfully to $CA_BUNDLE_PATH"
    fi
elif [[ "${DOCUMENTDB_HOST}" == *"docdb.amazonaws.com"* ]]; then
    echo "Detected regular DocumentDB cluster"
    echo "Downloading regular DocumentDB CA bundle..."
    CA_BUNDLE_URL="https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem"
    CA_BUNDLE_PATH="/app/global-bundle.pem"
    if [ ! -f "$CA_BUNDLE_PATH" ]; then
        curl -fsSL "$CA_BUNDLE_URL" -o "$CA_BUNDLE_PATH"
        echo "DocumentDB CA bundle (global-bundle.pem) downloaded successfully to $CA_BUNDLE_PATH"
    fi
else
    echo "No DocumentDB host detected or DOCUMENTDB_HOST is empty - skipping CA bundle download"
fi

# --- Wait for MongoDB Replica Set ---
if [ -n "$DOCUMENTDB_HOST" ]; then
    echo "Waiting for MongoDB replica set at ${DOCUMENTDB_HOST}:${DOCUMENTDB_PORT:-27017}..."
    source /app/.venv/bin/activate
    python3 -c "
import pymongo, os, time, sys
host = os.getenv('DOCUMENTDB_HOST', 'mongodb')
port = int(os.getenv('DOCUMENTDB_PORT', '27017'))
user = os.getenv('DOCUMENTDB_USERNAME', '')
pwd = os.getenv('DOCUMENTDB_PASSWORD', '')
backend = os.getenv('STORAGE_BACKEND', 'mongodb-ce')
auth = 'SCRAM-SHA-256' if backend == 'mongodb-ce' else 'SCRAM-SHA-1'
if user and pwd:
    uri = f'mongodb://{user}:{pwd}@{host}:{port}/?authMechanism={auth}&authSource=admin'
else:
    uri = f'mongodb://{host}:{port}/'
while True:
    try:
        c = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5000, connectTimeoutMS=5000)
        c.admin.command('ping')
        try:
            st = c.admin.command('replSetGetStatus')
            ready = [m for m in st['members'] if m['state'] in [1, 2]]
            total = len(st['members'])
            if st['ok'] == 1 and len(ready) == total:
                print(f'MongoDB replica set ready ({len(ready)}/{total} members)')
                c.close()
                break
            print(f'Waiting for replica set: {len(ready)}/{total} ready')
        except pymongo.errors.OperationFailure:
            # Standalone mode (no replica set) - ping succeeded so we're good
            print('MongoDB is ready (standalone mode)')
            c.close()
            break
    except Exception as e:
        print(f'MongoDB not ready yet: {e}')
    time.sleep(5)
"
    deactivate
    echo "MongoDB is ready."
fi

echo "Starting Auth Server..."
cd /app
source .venv/bin/activate
exec uvicorn server:app --host 0.0.0.0 --port 8888 --proxy-headers --forwarded-allow-ips='*'
