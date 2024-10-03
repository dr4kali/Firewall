import tkinter as tk
from tkinter import scrolledtext
import threading
import time

class LogViewer(tk.Tk):
    def __init__(self, log_file_path):
        super().__init__()
        self.title("Firewall Log Viewer")
        self.geometry("600x400")
        
        # Create a ScrolledText widget for displaying logs
        self.log_area = scrolledtext.ScrolledText(self, wrap=tk.WORD, state='normal')
        self.log_area.pack(expand=True, fill='both')

        # Set the path to the log file
        self.log_file_path = log_file_path
        
        # Start the log monitoring in a separate thread
        self.monitor_thread = threading.Thread(target=self.follow_log)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def follow_log(self):
        """ Continuously read new lines from the log file and update the GUI. """
        with open(self.log_file_path, 'r') as file:
            file.seek(0, 2)  # Move the cursor to the end of the file
            while True:
                line = file.readline()
                if not line:
                    time.sleep(1)  # Sleep briefly if no new line is available
                    continue
                self.update_log_area(line)

    def update_log_area(self, line):
        """ Update the ScrolledText widget with new log lines. """
        self.log_area.insert(tk.END, line)
        self.log_area.yview(tk.END)  # Scroll to the end of the widget

def main():
    log_file_path = 'var/firewall/log'  # Path to the log file
    viewer = LogViewer(log_file_path)
    viewer.mainloop()
    
if __name__ == "__main__":
    main()