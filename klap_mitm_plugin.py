#!/usr/bin/env python3
"""
Plugin for intercepting and decrypting KLAP protocol traffic for mitmproxy.

First close the app, start and configure the proxy on your device, then start the app.
Otherwise the handshake will not be captured and no decryption can be performed.
"""

import logging
import re
import json
import os
import time
import threading
import requests
from typing import Optional, Dict, Any
from mitmproxy import http, ctx
from decryptor import KlapDecryptor
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CommandFileHandler(FileSystemEventHandler):
    """File system event handler for watching to_send.json file."""
    
    def __init__(self, plugin_instance):
        self.plugin = plugin_instance
        self.last_modified = 0
        
    def on_modified(self, event):
        """Handle file modification events."""
        if event.is_directory:
            return
        
        if os.path.basename(event.src_path) == 'to_send.json':
            current_time = time.time()
            if current_time - self.last_modified < 0.5:
                return
            self.last_modified = current_time
            
            logger.info(f"Detected change in {event.src_path}")
            logger.info("Send a new command with the app in order to inject it. It will replace the real command.")
            threading.Thread(target=self.plugin.process_command_file, daemon=True).start()

class KlapMitmPlugin:
    """MITM Plugin for intercepting and decrypting KLAP protocol traffic."""
    
    def __init__(self):
        self._load_user_data()
        
        # Handshake tracking
        self.handshake1_request: Optional[str] = None
        self.handshake1_response: Optional[str] = None
        self.handshake2_request: Optional[str] = None
        self.handshake_complete = False
        
        # Decryptor instance
        self.decryptor: Optional[KlapDecryptor] = None
        
        # Session tracking
        self.session_cookie: Optional[str] = None
        self.sequence_number = 1  # Track sequence numbers
        self.last_request_headers: Dict[str, str] = {}  # Store headers from last request
        
        # File watching and command injection
        self.command_file_path = "to_send.json"
        self.file_observer = None
        self.pending_command: Optional[Dict[str, Any]] = None  # Command to inject
        self.start_file_watcher()
        
        logger.info(f"KLAP MITM Plugin initialized for device: {self.target_device}")
        logger.info(f"Watching for commands in: {self.command_file_path}")
    
    def _load_user_data(self):
        if "KLAP_TARGET_DEVICE" in os.environ:
            self.target_device = os.environ["KLAP_TARGET_DEVICE"]
        if "KLAP_USERNAME" in os.environ:
            self.username = os.environ["KLAP_USERNAME"]
        if "KLAP_PASSWORD" in os.environ:
            self.password = os.environ["KLAP_PASSWORD"]
    
    def _is_target_device(self, flow: http.HTTPFlow) -> bool:
        """Check if the request is to/from our target device."""
        return flow.request.pretty_host == self.target_device
    
    def _is_klap_handshake1(self, flow: http.HTTPFlow) -> bool:
        """Check if this is a KLAP handshake1 request."""
        return (
            flow.request.path.endswith("/handshake1") and
            flow.request.method == "POST"
        )
    
    def _is_klap_handshake2(self, flow: http.HTTPFlow) -> bool:
        """Check if this is a KLAP handshake2 request."""
        return (
            flow.request.path.endswith("/handshake2") and
            flow.request.method == "POST"
        )
    
    def _is_klap_request(self, flow: http.HTTPFlow) -> bool:
        """Check if this is a KLAP encrypted request."""
        return (
            flow.request.path.startswith("/app/request") and
            flow.request.method == "POST"
        )
    
    def _extract_sequence_from_url(self, url: str) -> Optional[int]:
        """Extract sequence number from request URL."""
        match = re.search(r'seq=(\d+)', url)
        if match:
            return int(match.group(1))
        return None
    
    def _bytes_to_hex(self, data: bytes) -> str:
        """Convert bytes to hex string."""
        return data.hex().upper()
    
    def _initialize_decryptor(self) -> bool:
        """Initialize the decryptor once we have all handshake data."""
        if not all([self.handshake1_request, self.handshake1_response, self.handshake2_request]):
            return False
        
        try:
            assert self.handshake1_request is not None
            assert self.handshake1_response is not None
            assert self.handshake2_request is not None
            
            self.decryptor = KlapDecryptor(
                self.handshake1_request,
                self.handshake1_response,
                self.handshake2_request,
                self.username,
                self.password
            )
            self.handshake_complete = True
            logger.info("KLAP Decryptor initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize KLAP Decryptor: {e}")
            return False
    
    def start_file_watcher(self):
        """Start watching the command file for changes."""
        try:
            self.file_observer = Observer()
            event_handler = CommandFileHandler(self)
            watch_path = os.path.dirname(os.path.abspath(self.command_file_path)) or "."
            self.file_observer.schedule(event_handler, watch_path, recursive=False)
            self.file_observer.start()
            logger.info(f"Started watching directory: {watch_path}")
        except Exception as e:
            logger.error(f"Failed to start file watcher: {e}")
    
    def stop_file_watcher(self):
        """Stop the file watcher."""
        if self.file_observer:
            self.file_observer.stop()
            self.file_observer.join()
            logger.info("File watcher stopped")
    
    def process_command_file(self):
        """Process the to_send.json file and queue commands for injection."""
        try:
            if not os.path.exists(self.command_file_path):
                logger.debug(f"Command file {self.command_file_path} does not exist")
                return
            
            with open(self.command_file_path, 'r') as f:
                content = f.read().strip()
            
            if not content:
                return
            
            try:
                command_data = json.loads(content)
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in command file: {e}")
                return
            
            if not self.decryptor or not self.handshake_complete:
                logger.warning("Cannot prepare command - KLAP session not established")
                return
            
            self.pending_command = command_data
            logger.info(f"📋 Command queued for injection: {json.dumps(command_data, indent=2)}")
            
            with open(self.command_file_path, 'w') as f:
                f.write('')
            logger.info("Command queued successfully - will inject into next outgoing request")
                
        except Exception as e:
            logger.error(f"Error processing command file: {e}")
    
    def shutdown(self):
        """Clean up resources when shutting down."""
        self.stop_file_watcher()
    
    def request(self, flow: http.HTTPFlow) -> None:
        """Handle incoming requests."""
        if not self._is_target_device(flow):
            return
        
        logger.info(f"Request: {flow.request.method} {flow.request.path}")
        
        if self._is_klap_handshake1(flow):
            if flow.request.content:
                self.handshake1_request = self._bytes_to_hex(flow.request.content)
                logger.info(f"🤝 Handshake1 Request captured: {self.handshake1_request}")
                flow.request.headers["X-KLAP-Type"] = "Handshake1-Request"
        
        elif self._is_klap_handshake2(flow):
            if flow.request.content:
                self.handshake2_request = self._bytes_to_hex(flow.request.content)
                logger.info(f"🤝 Handshake2 Request captured: {self.handshake2_request}")
                flow.request.headers["X-KLAP-Type"] = "Handshake2-Request"
                
                if self._initialize_decryptor():
                    logger.info("KLAP session established - ready to decrypt traffic")
        
        elif self._is_klap_request(flow):
            self.last_request_headers = dict(flow.request.headers)
            seq_num = self._extract_sequence_from_url(flow.request.url)
            if seq_num and seq_num > self.sequence_number:
                self.sequence_number = seq_num
            
            if self.pending_command and flow.request.content and seq_num:
                logger.info(f"Injecting custom command into request (seq: {seq_num})")
                
                command_json = json.dumps(self.pending_command)
                logger.info(f"Injecting command: {command_json}")
                
                try:
                    if self.decryptor is not None:
                        encrypted_data = self.decryptor.encrypt(seq_num, command_json)
                        flow.request.content = bytes.fromhex(encrypted_data)
                        flow.request.headers["X-KLAP-Injected"] = "true"
                        logger.info(f"Command injected successfully into sequence {seq_num}")
                        
                        data = {
                            "sequence": seq_num,
                            "injected_command": command_json,
                            "original_encrypted": self._bytes_to_hex(flow.request.content)
                        }
                        with open(f"messages/injected_{seq_num}.json", "w") as f:
                            json.dump(data, f, indent=4)
                        
                        self.pending_command = None
                    else:
                        logger.error("Cannot inject command: decryptor is not initialized")
                except Exception as e:
                    logger.error(f"Failed to inject command: {e}")
            
            if flow.request.content:
                encrypted_data = self._bytes_to_hex(flow.request.content)
                
                flow.request.headers["X-KLAP-Type"] = "Encrypted-Request"
                flow.request.headers["X-KLAP-Sequence"] = str(seq_num) if seq_num else "unknown"
                
                logger.info(f"Encrypted Request (seq: {seq_num}): {len(encrypted_data)} chars")
                
                if self.decryptor and seq_num:
                    try:
                        decrypted = self.decryptor.decrypt(seq_num, encrypted_data, verify_signature=False)
                        logger.info(f"Decrypted Request: {decrypted}")
                        flow.request.headers["X-KLAP-Decrypted"] = decrypted[:200] + "..." if len(decrypted) > 200 else decrypted
                        
                        data = {
                            "sequence": seq_num,
                            "request": decrypted
                        }
                        with open(f"messages/decrypted_{seq_num}.json", "w") as f:
                            json.dump(data, f, indent=4)
                        
                    except Exception as e:
                        logger.error(f"Failed to decrypt request: {e}")
                        flow.request.headers["X-KLAP-Decrypt-Error"] = str(e)
    
    def response(self, flow: http.HTTPFlow) -> None:
        """Handle responses."""
        if not self._is_target_device(flow) or not flow.response:
            return
        
        logger.info(f"Response: {flow.response.status_code} for {flow.request.path}")
        
        if self._is_klap_handshake1(flow):
            if flow.response.content:
                self.handshake1_response = self._bytes_to_hex(flow.response.content)
                logger.info(f"🤝 Handshake1 Response captured: {self.handshake1_response}")
                flow.response.headers["X-KLAP-Type"] = "Handshake1-Response"
                
                if "Set-Cookie" in flow.response.headers:
                    cookies = flow.response.headers.get_all("Set-Cookie")
                    for cookie in cookies:
                        if "TP_SESSIONID" in cookie:
                            self.session_cookie = cookie
                            logger.info(f"Session cookie captured: {cookie}")
        
        elif self._is_klap_handshake2(flow):
            logger.info(f"Handshake2 Response: Status {flow.response.status_code}")
            flow.response.headers["X-KLAP-Type"] = "Handshake2-Response"
        
        elif self._is_klap_request(flow):
            seq_num = self._extract_sequence_from_url(flow.request.url)
            if flow.response.content:
                encrypted_data = self._bytes_to_hex(flow.response.content)
                
                flow.response.headers["X-KLAP-Type"] = "Encrypted-Response"
                flow.response.headers["X-KLAP-Sequence"] = str(seq_num) if seq_num else "unknown"
                
                logger.info(f"Encrypted Response (seq: {seq_num}): {len(encrypted_data)} chars")
                
                if self.decryptor and seq_num and encrypted_data:
                    try:
                        decrypted = self.decryptor.decrypt(seq_num, encrypted_data, verify_signature=False)
                        logger.info(f"Decrypted Response: {decrypted}")
                        flow.response.headers["X-KLAP-Decrypted"] = decrypted[:200] + "..." if len(decrypted) > 200 else decrypted
                        
                        try:
                            with open(f"messages/decrypted_{seq_num}.json", "r") as existing_file:
                                existing_data = json.load(existing_file)
                        except FileNotFoundError:
                            existing_data = {}
                        
                        if isinstance(existing_data, dict):
                            existing_data["response"] = decrypted
                            with open(f"messages/decrypted_{seq_num}.json", "w") as f:
                                json.dump(existing_data, f, indent=4)
                            
                    except Exception as e:
                        logger.error(f"Failed to decrypt response: {e}")
                        flow.response.headers["X-KLAP-Decrypt-Error"] = str(e)
    
    def log(self, entry):
        """Handle log entries."""
        if "KLAP" in str(entry.msg):
            ctx.log.info(f"KLAP: {entry.msg}")


klap_plugin = KlapMitmPlugin()

def request(flow: http.HTTPFlow) -> None:
    """mitmproxy request handler."""
    klap_plugin.request(flow)

def response(flow: http.HTTPFlow) -> None:
    """mitmproxy response handler."""
    klap_plugin.response(flow)

def load(loader):
    """Called when the plugin is loaded."""
    ctx.log.info("🚀 KLAP MITM Plugin loaded successfully")

def done():
    """Called when mitmproxy is shutting down."""
    klap_plugin.shutdown()
    ctx.log.info("KLAP MITM Plugin shutting down")
