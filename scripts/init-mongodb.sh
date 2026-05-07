#!/bin/bash
# Initialize MongoDB replica set and create vector search indexes
# For MongoDB Community Edition local development

set -e

DOCUMENTDB_HOST="${DOCUMENTDB_HOST:-mongodb}"
DOCUMENTDB_PORT="${DOCUMENTDB_PORT:-27017}"
DOCUMENTDB_USERNAME="${DOCUMENTDB_USERNAME:-admin}"
DOCUMENTDB_PASSWORD="${DOCUMENTDB_PASSWORD:-admin}"
DOCUMENTDB_DATABASE="${DOCUMENTDB_DATABASE:-mcp_registry}"
DOCUMENTDB_NAMESPACE="${DOCUMENTDB_NAMESPACE:-default}"

# MONGODB_CONNECTION_STRING override: when set, use the URI verbatim and skip
# replSetInitiate (caller's cluster is assumed to already be configured, e.g.
# MongoDB Atlas or any externally-managed replica set).
if [ -n "${MONGODB_CONNECTION_STRING:-}" ]; then
  MONGO_URL="$MONGODB_CONNECTION_STRING"
  SKIP_REPLSET_INIT=1
else
  MONGO_URL=""
  SKIP_REPLSET_INIT=0
fi

echo "=========================================="
echo "MongoDB Initialization for MCP Gateway"
echo "=========================================="
if [ "$SKIP_REPLSET_INIT" = "1" ]; then
  echo "Host: (connection string override)"
else
  echo "Host: $DOCUMENTDB_HOST:$DOCUMENTDB_PORT"
fi
echo "Database: $DOCUMENTDB_DATABASE"
echo "Namespace: $DOCUMENTDB_NAMESPACE"
echo ""

echo "Waiting for MongoDB to be ready..."
sleep 10

if [ "$SKIP_REPLSET_INIT" = "1" ]; then
  echo "Skipping replica-set initialization (connection string override in use)"
else
  echo "Initializing MongoDB replica set..."
  # Check if authentication is configured
  if [ -n "$DOCUMENTDB_USERNAME" ] && [ -n "$DOCUMENTDB_PASSWORD" ] && [ "$DOCUMENTDB_USERNAME" != "admin" ] || [ "$DOCUMENTDB_PASSWORD" != "admin" ]; then
    MONGO_URL="mongodb://$DOCUMENTDB_USERNAME:$DOCUMENTDB_PASSWORD@$DOCUMENTDB_HOST:$DOCUMENTDB_PORT/admin"
  else
    MONGO_URL="mongodb://$DOCUMENTDB_HOST:$DOCUMENTDB_PORT"
  fi
  mongosh "$MONGO_URL" <<EOF
// Initialize replica set (required for transactions and vector search)
try {
  rs.initiate({
    _id: "rs0",
    members: [
      { _id: 0, host: "$DOCUMENTDB_HOST:$DOCUMENTDB_PORT" }
    ]
  });
  print("Replica set initialized");
} catch (e) {
  if (e.codeName === 'AlreadyInitialized') {
    print("Replica set already initialized");
  } else {
    throw e;
  }
}
EOF

  echo "Waiting for replica set to elect primary..."
  sleep 10
fi

echo "Creating database and collections with indexes..."
mongosh "$MONGO_URL" <<EOF
// Switch to mcp_registry database
use $DOCUMENTDB_DATABASE;

// Collection 1: MCP Servers
const serversCollection = "mcp_servers_$DOCUMENTDB_NAMESPACE";
print("Creating collection: " + serversCollection);
db.createCollection(serversCollection);
db[serversCollection].createIndex({ path: 1 }, { unique: true });
db[serversCollection].createIndex({ enabled: 1 });
db[serversCollection].createIndex({ tags: 1 });
db[serversCollection].createIndex({ "manifest.serverInfo.name": 1 });
print("✓ " + serversCollection + " indexes created");

// Collection 2: MCP Agents
const agentsCollection = "mcp_agents_$DOCUMENTDB_NAMESPACE";
print("Creating collection: " + agentsCollection);
db.createCollection(agentsCollection);
db[agentsCollection].createIndex({ path: 1 }, { unique: true });
db[agentsCollection].createIndex({ enabled: 1 });
db[agentsCollection].createIndex({ tags: 1 });
db[agentsCollection].createIndex({ "card.name": 1 });
print("✓ " + agentsCollection + " indexes created");

// Collection 3: OAuth Scopes
const scopesCollection = "mcp_scopes_$DOCUMENTDB_NAMESPACE";
print("Creating collection: " + scopesCollection);
db.createCollection(scopesCollection);
// No additional indexes needed - scopes use _id as primary key
// group_mappings is an array, not indexed
print("✓ " + scopesCollection + " indexes created");

// Collection 4: Vector Embeddings (1536 dimensions for Titan/OpenAI)
const embeddingsCollection = "mcp_embeddings_1536_$DOCUMENTDB_NAMESPACE";
print("Creating collection: " + embeddingsCollection);
db.createCollection(embeddingsCollection);
db[embeddingsCollection].createIndex({ path: 1 }, { unique: true });
db[embeddingsCollection].createIndex({ entity_type: 1 });

// Vector search index for MongoDB CE
// Note: MongoDB CE 8.2 vector search is implemented at the application level
// See registry/repositories/documentdb/search_repository.py for semantic search implementation
print("✓ " + embeddingsCollection + " indexes created (vector search via app code)");

// Collection 5: Security Scans
const scansCollection = "mcp_security_scans_$DOCUMENTDB_NAMESPACE";
print("Creating collection: " + scansCollection);
db.createCollection(scansCollection);
db[scansCollection].createIndex({ server_path: 1 });
db[scansCollection].createIndex({ scan_status: 1 });
db[scansCollection].createIndex({ scanned_at: -1 });
print("✓ " + scansCollection + " indexes created");

// Collection 6: Federation Configuration
const federationCollection = "mcp_federation_config_$DOCUMENTDB_NAMESPACE";
print("Creating collection: " + federationCollection);
db.createCollection(federationCollection);
db[federationCollection].createIndex({ registry_name: 1 }, { unique: true });
db[federationCollection].createIndex({ enabled: 1 });
print("✓ " + federationCollection + " indexes created");

print("");
print("========================================");
print("MongoDB Initialization Complete!");
print("========================================");
print("Collections created:");
print("  • " + serversCollection);
print("  • " + agentsCollection);
print("  • " + scopesCollection);
print("  • " + embeddingsCollection + " (with vector search)");
print("  • " + scansCollection);
print("  • " + federationCollection);
print("");
print("To use MongoDB CE:");
print("  export STORAGE_BACKEND=mongodb-ce");
print("  docker-compose up registry");
print("");
print("Or for AWS DocumentDB:");
print("  export STORAGE_BACKEND=documentdb");
print("  docker-compose up registry");
print("========================================");
EOF

echo ""
echo "✓ MongoDB initialization complete!"
