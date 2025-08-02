#!/bin/bash

if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
    echo "Virtual environment activated"
else
    echo "No virtual environment found. Using system's python..."
fi

if [ ! -d "messages" ]; then
    echo "Creating messages directory..."
    mkdir -p messages
fi

echo "Launching KLAP Viewer GUI..."
python3 klap_viewer.py
