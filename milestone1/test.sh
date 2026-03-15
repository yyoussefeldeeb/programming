#!/bin/bash
# Quick test script for the secure communication system
# Run this on Ubuntu after compilation

echo "=== Secure Communication System Test ==="
echo ""

if [ ! -f "build/server" ] || [ ! -f "build/client" ]; then
    echo "Error: Executables not found. Run 'make' first."
    exit 1
fi

echo "[1] Starting server in background..."
./build/server &
SERVER_PID=$!
sleep 1

echo "[2] Starting client..."
./build/client

echo ""
echo "[3] Terminating server..."
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo ""
echo "=== Test Complete ==="
