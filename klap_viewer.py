#!/usr/bin/env python3
"""
Simple GUI to view decrypted requests and their corresponding responses.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import json
import os
import time
import threading
from typing import Dict, List, Any, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import re
from datetime import datetime

class MessageData:
    """Class to hold message data."""
    def __init__(self, sequence: int, request: str = "", response: str = "", timestamp: str = "", modification_time: float = 0):
        self.sequence = sequence
        self.request = request
        self.response = response
        self.timestamp = timestamp or datetime.now().strftime("%H:%M:%S")
        self.modification_time = modification_time or time.time()

class MessageFileHandler(FileSystemEventHandler):
    """File system event handler for monitoring message files."""
    
    def __init__(self, viewer):
        self.viewer = viewer
        super().__init__()
    
    def on_created(self, event):
        if not event.is_directory and str(event.src_path).endswith('.json'):
            threading.Timer(0.1, lambda: self.viewer.load_message_file(event.src_path)).start()
    
    def on_modified(self, event):
        if not event.is_directory and str(event.src_path).endswith('.json'):
            threading.Timer(0.1, lambda: self.viewer.load_message_file(event.src_path)).start()

class KlapViewer:
    """Main GUI application for viewing KLAP messages."""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("KLAP Message Viewer")
        self.root.geometry("1400x800")
        self.root.configure(bg='#f0f0f0')
        
        self.messages: Dict[int, MessageData] = {}
        self.selected_sequence: Optional[int] = None
        
        self.messages_dir = "messages"
        self.observer = None
        
        self.message_list: Optional[tk.Listbox] = None
        self.request_text: Optional[scrolledtext.ScrolledText] = None
        self.response_text: Optional[scrolledtext.ScrolledText] = None
        self.status_label: Optional[tk.Label] = None
        self.filter_var: Optional[tk.StringVar] = None
        
        self.setup_gui()
        self.setup_file_monitoring()
        self.load_existing_messages()
        
        self.root.after(1000, self.periodic_update)
    
    def setup_gui(self):
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        control_frame = tk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        filter_frame = tk.Frame(control_frame)
        filter_frame.pack(side=tk.LEFT)
        
        tk.Label(filter_frame, text="Filter:", fg='black').pack(side=tk.LEFT, padx=(0, 5))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add('write', self.on_filter_change)
        filter_entry = tk.Entry(filter_frame, textvariable=self.filter_var, width=30)
        filter_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        buttons_frame = tk.Frame(control_frame)
        buttons_frame.pack(side=tk.RIGHT)
        
        refresh_btn = tk.Button(buttons_frame, text="Refresh", command=self.refresh_messages, 
                               bg='#e1e1e1', fg='black', relief=tk.RAISED)
        refresh_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        clear_btn = tk.Button(buttons_frame, text="Clear Selection", command=self.clear_selection,
                             bg='#e1e1e1', fg='black', relief=tk.RAISED)
        clear_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        export_btn = tk.Button(buttons_frame, text="Export All", command=self.export_messages,
                              bg='#e1e1e1', fg='black', relief=tk.RAISED)
        export_btn.pack(side=tk.LEFT)
        
        content_frame = tk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        left_frame = tk.Frame(content_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 5))
        
        tk.Label(left_frame, text="Messages (Sequence)", fg='black', font=('Arial', 12, 'bold')).pack(pady=(0, 5))
        
        list_frame = tk.Frame(left_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar_list = tk.Scrollbar(list_frame)
        scrollbar_list.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.message_list = tk.Listbox(list_frame, yscrollcommand=scrollbar_list.set,
                                      width=40, bg='white', fg='black',
                                      selectbackground='#0078d4', selectforeground='white',
                                      font=('Courier', 10))
        self.message_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.message_list.bind('<<ListboxSelect>>', self.on_message_select)
        
        scrollbar_list.config(command=self.message_list.yview)
        
        middle_frame = tk.Frame(content_frame)
        middle_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        tk.Label(middle_frame, text="Request", fg='black', font=('Arial', 12, 'bold')).pack(pady=(0, 5))
        
        self.request_text = scrolledtext.ScrolledText(middle_frame, wrap=tk.WORD, 
                                                     bg='white', fg='black',
                                                     insertbackground='black',
                                                     font=('Courier', 10))
        self.request_text.pack(fill=tk.BOTH, expand=True)
        
        right_frame = tk.Frame(content_frame)
        right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        tk.Label(right_frame, text="Response", fg='black', font=('Arial', 12, 'bold')).pack(pady=(0, 5))
        
        self.response_text = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD,
                                                      bg='white', fg='black',
                                                      insertbackground='black',
                                                      font=('Courier', 10))
        self.response_text.pack(fill=tk.BOTH, expand=True)
        
        status_frame = tk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.status_label = tk.Label(status_frame, text="Ready - Monitoring messages directory...",
                                    bg='#e0e0e0', fg='#333333', font=('Arial', 9))
        self.status_label.pack(side=tk.LEFT)
        
        self.setup_context_menus()
    
    def setup_context_menus(self):
        def make_context_menu(text_widget):
            menu = tk.Menu(self.root, tearoff=0)
            menu.add_command(label="Copy", command=lambda: self.copy_text(text_widget))
            menu.add_command(label="Select All", command=lambda: self.select_all_text(text_widget))
            
            def show_context_menu(event):
                try:
                    menu.tk_popup(event.x_root, event.y_root)
                finally:
                    menu.grab_release()
            
            text_widget.bind("<Button-2>", show_context_menu)
            return menu
        
        make_context_menu(self.request_text)
        make_context_menu(self.response_text)
    
    def copy_text(self, text_widget):
        try:
            selected_text = text_widget.selection_get()
            self.root.clipboard_clear()
            self.root.clipboard_append(selected_text)
        except tk.TclError:
            pass
    
    def select_all_text(self, text_widget):
        text_widget.tag_add(tk.SEL, "1.0", tk.END)
        text_widget.mark_set(tk.INSERT, "1.0")
        text_widget.see(tk.INSERT)
    
    def setup_file_monitoring(self):
        if not os.path.exists(self.messages_dir):
            os.makedirs(self.messages_dir)
        
        self.observer = Observer()
        handler = MessageFileHandler(self)
        self.observer.schedule(handler, self.messages_dir, recursive=False)
        self.observer.start()
    
    def load_existing_messages(self):
        if not os.path.exists(self.messages_dir):
            return
        
        for filename in os.listdir(self.messages_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(self.messages_dir, filename)
                self.load_message_file(filepath)
        
        self.update_message_list()
    
    def load_message_file(self, filepath: str):
        try:
            filename = os.path.basename(filepath)
            match = re.search(r'decrypted_(\d+)\.json', filename)
            if not match:
                return
            
            sequence = int(match.group(1))
            
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            if isinstance(data, list):
                if data:
                    latest_data = data[-1]
                    request = latest_data.get('request', '')
                    response = latest_data.get('response', '')
                else:
                    request = response = ''
            else:
                request = data.get('request', '')
                response = data.get('response', '')
            
            modification_time = os.path.getmtime(filepath)
            timestamp = datetime.fromtimestamp(modification_time).strftime("%H:%M:%S")
            
            self.messages[sequence] = MessageData(sequence, request, response, timestamp, modification_time)
            
            self.root.after_idle(self.update_message_list)
            
        except Exception as e:
            print(f"Error loading message file {filepath}: {e}")
    
    def update_message_list(self):
        if not self.message_list or not self.status_label or not self.filter_var:
            return
            
        current_selection = self.message_list.curselection()
        current_sequence = None
        if current_selection:
            current_text = self.message_list.get(current_selection[0])
            seq_match = re.search(r'(\d+)', current_text)
            if seq_match:
                current_sequence = int(seq_match.group(1))
        
        self.message_list.delete(0, tk.END)
        
        filter_text = self.filter_var.get().lower()
        
        sorted_messages = sorted(self.messages.items(), 
                               key=lambda item: (-item[1].modification_time, item[0]), 
                               reverse=False)
        
        for sequence, message in sorted_messages:
            message = self.messages[sequence]
            
            if filter_text:
                search_text = f"{sequence} {message.request} {message.response}".lower()
                if filter_text not in search_text:
                    continue
            
            has_request = "✓" if message.request else "✗"
            has_response = "✓" if message.response else "✗"
            display_text = f"{sequence} [{has_request}R/{has_response}S] {message.timestamp}"
            
            self.message_list.insert(tk.END, display_text)
            
            if sequence == current_sequence:
                self.message_list.selection_set(tk.END)
        
        total_messages = len(self.messages)
        displayed_messages = self.message_list.size()
        if filter_text:
            status_text = f"Showing {displayed_messages}/{total_messages} messages (filtered)"
        else:
            status_text = f"Loaded {total_messages} messages"
        
        self.status_label.config(text=status_text)
    
    def on_message_select(self, event):
        if not self.message_list or not self.request_text or not self.response_text:
            return
            
        selection = self.message_list.curselection()
        if not selection:
            return
        
        selected_text = self.message_list.get(selection[0])
        seq_match = re.search(r'(\d+)', selected_text)
        if not seq_match:
            return
        
        sequence = int(seq_match.group(1))
        self.selected_sequence = sequence
        
        if sequence in self.messages:
            message = self.messages[sequence]
            
            self.request_text.delete(1.0, tk.END)
            if message.request:
                try:
                    formatted_request = json.dumps(json.loads(message.request), indent=2)
                    self.request_text.insert(1.0, formatted_request)
                except (json.JSONDecodeError, TypeError):
                    self.request_text.insert(1.0, message.request)
            else:
                self.request_text.insert(1.0, "No request data")
            
            self.response_text.delete(1.0, tk.END)
            if message.response:
                try:
                    formatted_response = json.dumps(json.loads(message.response), indent=2)
                    self.response_text.insert(1.0, formatted_response)
                except (json.JSONDecodeError, TypeError):
                    self.response_text.insert(1.0, message.response)
            else:
                self.response_text.insert(1.0, "No response data")
    
    def on_filter_change(self, *args):
        self.update_message_list()
    
    def clear_selection(self):
        if not self.message_list or not self.request_text or not self.response_text:
            return
            
        self.message_list.selection_clear(0, tk.END)
        self.request_text.delete(1.0, tk.END)
        self.response_text.delete(1.0, tk.END)
        self.selected_sequence = None
    
    def refresh_messages(self):
        self.messages.clear()
        self.load_existing_messages()
        if self.status_label:
            self.status_label.config(text="Messages refreshed")
    
    def export_messages(self):
        if not self.messages:
            messagebox.showwarning("Export", "No messages to export")
            return
        
        try:
            export_data = []
            for sequence in sorted(self.messages.keys()):
                message = self.messages[sequence]
                export_data.append({
                    "sequence": sequence,
                    "timestamp": message.timestamp,
                    "request": message.request,
                    "response": message.response
                })
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"klap_export_{timestamp}.json"
            
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            messagebox.showinfo("Export", f"Messages exported to {filename}")
            if self.status_label:
                self.status_label.config(text=f"Exported to {filename}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export messages: {e}")
    
    def periodic_update(self):
        self.root.after(1000, self.periodic_update)
    
    def run(self):
        try:
            self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
            self.root.mainloop()
        except KeyboardInterrupt:
            self.on_closing()
    
    def on_closing(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
        self.root.quit()
        self.root.destroy()

def main():
    print("Starting KLAP Message Viewer...")
    
    if not os.path.exists("messages"):
        print("Creating messages directory...")
        os.makedirs("messages")
    
    viewer = KlapViewer()
    viewer.run()

if __name__ == "__main__":
    main()
