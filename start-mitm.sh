#!/bin/bash

if [ -d ".venv" ]; then
    source .venv/bin/activate
else
    echo "Creating virtual environment..."
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
fi

prompt_for_env_var() {
    local var_name="$1"
    local prompt_message="$2"
    local var_value="${!var_name}"

    if [ -z "$var_value" ]; then
        echo "Environment variable $var_name is not set. Enter it now:"
        read -r input_value
        export "$var_name"="$input_value"
    fi
}

prompt_for_env_var "KLAP_TARGET_DEVICE"
prompt_for_env_var "KLAP_USERNAME"
prompt_for_env_var "KLAP_PASSWORD"

echo "Target device: $KLAP_TARGET_DEVICE"

ESCAPED_TARGET_DEVICE=$(echo "$KLAP_TARGET_DEVICE" | sed 's/\./\\./g')
touch to_send.json

mitmweb \
    --listen-port 9000 \
    --web-port 8081 \
    --mode regular \
    --set ssl_insecure=true \
    --scripts klap_mitm_plugin.py \
    --set confdir="$HOME/.mitmproxy" \
    --set ignore_hosts="^(?!$ESCAPED_TARGET_DEVICE)" \
    --quiet \
    --set flow_detail=0