tapo-klap-mitm
=========================

This codebase provides tools for intercepting, decrypting, and visualizing KLAP protocol traffic from tapo smart vacuum robots.

Main Components:
----------------
1. klap_mitm_plugin.py
   - mitmproxy plugin for intercepting KLAP traffic, decrypting requests/responses, and injecting commands.
   - Requires environment variables: KLAP_TARGET_DEVICE, KLAP_USERNAME, KLAP_PASSWORD.
   - Stores decrypted messages in the 'messages' directory.

2. klap_viewer.py
   - GUI application to view decrypted KLAP requests and responses.
   - Run with: python3 klap_viewer.py

3. vacuum_map_converter.py
   - Converts KLAP map response JSON files to PNG floor plan images.
   - Run with: python3 vacuum_map_converter.py [input_file.json]

4. decryptor.py
   - Implements KLAP protocol decryption and encryption logic.

5. start-mitm.sh
   - Shell script to start mitmproxy with the KLAP plugin and required environment variables.

Setup:
------
- Install dependencies: pip install -r requirements.txt
- Set environment variables for your device and credentials.
- Start mitmproxy using start-mitm.sh.
- Use klap_viewer.py to view decrypted messages.
- Use vacuum_map_converter.py to convert map responses to images.

Directory Structure:
--------------------
- messages/: Stores decrypted KLAP messages and injected commands.
- to_send.json: Used for command injection via mitmproxy plugin.

For more details, see comments in each script.

Acknowledgements:
-----------------
Special thanks to the python-kasa contributors for their work on the KLAP protocol.