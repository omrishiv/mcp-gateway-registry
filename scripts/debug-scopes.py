#!/usr/bin/env python3
"""Debug script to inspect DocumentDB scopes collection."""

import asyncio
import json
import os

from motor.motor_asyncio import AsyncIOMotorClient


async def debug_scopes():
    """Inspect DocumentDB scopes collection."""
    # Get connection details from environment
    override = os.getenv("MONGODB_CONNECTION_STRING", "")
    host = os.getenv("DOCUMENTDB_HOST", "localhost")
    port = int(os.getenv("DOCUMENTDB_PORT", "27017"))
    username = os.getenv("DOCUMENTDB_USERNAME")
    password = os.getenv("DOCUMENTDB_PASSWORD")
    database = os.getenv("DOCUMENTDB_DATABASE", "mcp_registry")
    namespace = os.getenv("DOCUMENTDB_NAMESPACE", "default")
    use_tls = os.getenv("DOCUMENTDB_USE_TLS", "true").lower() == "true"
    ca_file = os.getenv("DOCUMENTDB_TLS_CA_FILE", "/app/certs/global-bundle.pem")

    print("=" * 80)
    print("DocumentDB Scopes Debug")
    print("=" * 80)
    if override:
        from urllib.parse import urlsplit

        print(f"Host: {urlsplit(override).hostname or '(override)'} (connection string override)")
    else:
        print(f"Host: {host}:{port}")
    print(f"Database: {database}")
    print(f"Namespace: {namespace}")
    print(f"TLS: {use_tls}")
    print("=" * 80)
    print()

    if override:
        # URI owns all options: auth, TLS, retryWrites, replica set.
        connection_string = override
        client_kwargs: dict = {}
    else:
        # Build connection string with appropriate auth mechanism
        # Choose auth mechanism based on storage backend from environment
        storage_backend = os.getenv("STORAGE_BACKEND", "documentdb")
        if storage_backend == "mongodb-ce":
            auth_mechanism = "SCRAM-SHA-256"
        else:
            auth_mechanism = "SCRAM-SHA-1"

        if username and password:
            connection_string = f"mongodb://{username}:{password}@{host}:{port}/{database}?authMechanism={auth_mechanism}&authSource=admin"
        else:
            connection_string = f"mongodb://{host}:{port}/{database}"

        # TLS options
        tls_options: dict = {}
        if use_tls:
            tls_options["tls"] = True
            if ca_file and os.path.exists(ca_file):
                tls_options["tlsCAFile"] = ca_file
                print(f"Using CA file: {ca_file}")
            else:
                print(f"WARNING: CA file not found: {ca_file}")

        # DocumentDB does not support retryable writes
        client_kwargs = {"retryWrites": False, **tls_options}

    # Connect to DocumentDB
    print("Connecting to DocumentDB...")
    client = AsyncIOMotorClient(connection_string, **client_kwargs)
    db = client[database]

    try:
        # Test connection
        server_info = await client.server_info()
        print(f"Connected to MongoDB/DocumentDB version: {server_info.get('version')}")
        print()

        # Collection name
        collection_name = f"mcp_scopes_{namespace}"
        collection = db[collection_name]

        # Count documents
        count = await collection.count_documents({})
        print(f"Collection: {collection_name}")
        print(f"Document count: {count}")
        print()

        if count == 0:
            print("WARNING: No scope documents found!")
            print()
            print("Listing all collections:")
            collections = await db.list_collection_names()
            for coll in sorted(collections):
                print(f"  - {coll}")
        else:
            print("Scope documents:")
            print("-" * 80)

            # Get all scope documents
            cursor = collection.find({})
            async for doc in cursor:
                scope_id = doc.get("_id", "unknown")
                server_access = doc.get("server_access", [])
                group_mappings = doc.get("group_mappings", [])
                ui_permissions = doc.get("ui_permissions", {})

                print(f"\nScope ID: {scope_id}")
                print(f"  Group Mappings: {group_mappings}")
                print(f"  Server Access Rules: {len(server_access)} rules")

                if server_access:
                    print("  Server Access:")
                    for rule in server_access:
                        print(f"    - {json.dumps(rule, indent=6)}")

                if ui_permissions:
                    print(f"  UI Permissions: {json.dumps(ui_permissions, indent=4)}")

        print()
        print("=" * 80)

    finally:
        client.close()


if __name__ == "__main__":
    asyncio.run(debug_scopes())
