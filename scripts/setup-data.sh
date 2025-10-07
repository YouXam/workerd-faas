#!/bin/bash

# Clean up existing data directory
rm -rf data

# Create fresh data directory structure
mkdir -p data/do
mkdir -p data/files

echo "Data directory initialized successfully"
