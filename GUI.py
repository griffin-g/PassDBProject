import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import datetime
import os
from Backend import BreachedPasswordsDB

class BreachedPasswordsApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Breached Passwords Database")
        self.root.geometry("800x600")

        # Initialize database - with error handling
        try:
            self.db = BreachedPasswordsDB()
            db_connected = hasattr(self.db, 'cursor') and self.db.cursor is not None
        except Exception as e:
            db_connected = False
            messagebox.showwarning("Database Connection",
                                   f"Could not connect to database: {str(e)}\n\nSome features may be limited.")

        # Create notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Create tabs
        self.password_tab = ttk.Frame(self.notebook)
        self.breach_tab = ttk.Frame(self.notebook)
        self.encryption_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.password_tab, text="Password Lookup")
        self.notebook.add(self.breach_tab, text="Breach Information")
        self.notebook.add(self.encryption_tab, text="Encryption Methods")

        self._setup_password_tab()
        self._setup_breach_tab()
        self._setup_encryption_tab()

        if not db_connected:
            self._show_db_error_message()

        # Ensure DB connection is closed when app is closed
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _show_db_error_message(self):
        """Display database error messages in all tabs"""
        for tab in [self.password_tab, self.breach_tab, self.encryption_tab]:
            error_frame = ttk.Frame(tab)
            error_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

            ttk.Label(error_frame,
                      text="Database connection is not available.",
                      foreground="red").pack(pady=5)

    def _setup_password_tab(self):
        # Password lookup frame
        frame = ttk.LabelFrame(self.password_tab, text="Check if your password has been compromised")
        frame.pack(fill='both', expand=True, padx=10, pady=10)

        # Password entry
        ttk.Label(frame, text="Enter a password:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.password_entry = ttk.Entry(frame, show="*", width=30)
        self.password_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)

        # Show/hide password checkbox
        self.show_password_var = tk.BooleanVar()
        show_password_check = ttk.Checkbutton(frame, text="Show password",
                                              variable=self.show_password_var,
                                              command=self._toggle_password_visibility)
        show_password_check.grid(row=0, column=2, padx=5, pady=5)

        # Check button
        check_button = ttk.Button(frame, text="Check Password", command=self._check_password)
        check_button.grid(row=1, column=1, padx=5, pady=5)

        # Results area
        ttk.Label(frame, text="Results:").grid(row=2, column=0, sticky=tk.NW, padx=5, pady=5)
        self.results_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=70, height=20)
        self.results_text.grid(row=2, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")
        self.results_text.config(state=tk.DISABLED)

        # Configure grid weights
        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)
        frame.columnconfigure(2, weight=1)
        frame.rowconfigure(2, weight=1)

        # Import Wordlist
        import_button = ttk.Button(frame, text="Import Wordlist", command=self._import_wordlist)
        import_button.grid(row=3, column=1, padx=5, pady=5)

    def _setup_breach_tab(self):
        # Breach information frame
        frame = ttk.LabelFrame(self.breach_tab, text="Recent Breaches")
        frame.pack(fill='both', expand=True, padx=10, pady=10)

        # Recent breaches list
        ttk.Label(frame, text="Select a breach to view details:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)

        # Listbox for breaches
        self.breach_listbox = tk.Listbox(frame, width=70, height=10)
        self.breach_listbox.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        self.breach_listbox.bind('<<ListboxSelect>>', self._on_breach_selected)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.breach_listbox.yview)
        scrollbar.grid(row=1, column=1, sticky="ns")
        self.breach_listbox.configure(yscrollcommand=scrollbar.set)

        # Breach details area
        ttk.Label(frame, text="Breach Details:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.breach_details_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=70, height=15)
        self.breach_details_text.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")
        self.breach_details_text.config(state=tk.DISABLED)

        # Refresh button
        refresh_button = ttk.Button(frame, text="Refresh Breaches", command=self._load_recent_breaches)
        refresh_button.grid(row=4, column=0, padx=5, pady=5)

        # Configure grid weights
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)
        frame.rowconfigure(3, weight=2)

        # Load recent breaches
        self._load_recent_breaches()

    def _setup_encryption_tab(self):
        # Encryption methods frame
        frame = ttk.LabelFrame(self.encryption_tab, text="Encryption Methods & Benchmarks")
        frame.pack(fill='both', expand=True, padx=10, pady=10)

        # Encryption methods list
        ttk.Label(frame, text="Available Encryption Methods:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)

        # Listbox for encryption methods
        self.encryption_listbox = tk.Listbox(frame, width=70, height=10)
        self.encryption_listbox.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        self.encryption_listbox.bind('<<ListboxSelect>>', self._on_encryption_selected)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.encryption_listbox.yview)
        scrollbar.grid(row=1, column=1, sticky="ns")
        self.encryption_listbox.configure(yscrollcommand=scrollbar.set)

        # Encryption details area
        ttk.Label(frame, text="Encryption Method Details:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.encryption_details_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=70, height=15)
        self.encryption_details_text.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")
        self.encryption_details_text.config(state=tk.DISABLED)

        # Configure grid weights
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)
        frame.rowconfigure(3, weight=2)

        # Load encryption methods
        self._load_encryption_methods()

    def _toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def _check_password(self):
        password = self.password_entry.get().strip()
        if not password:
            messagebox.showerror("Error", "Please enter a password to check")
            return

        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)

        if not hasattr(self, 'db') or not hasattr(self.db, 'cursor') or self.db.cursor is None:
            self.results_text.insert(tk.END, "⚠️ Database connection is not available. Unable to check password.\n")
            self.results_text.config(state=tk.DISABLED)
            return

        # Check if password exists in database
        password_info = self.db.check_password(password)

        if password_info:
            self.results_text.insert(tk.END, f"PASSWORD FOUND IN BREACHES ⚠️\n\n")
            self.results_text.insert(tk.END,
                                     f"This password has been found in {password_info['breach_count']} breach(es).\n\n")
            self.results_text.insert(tk.END, f"Password strength: {password_info['Strength']}/10\n")
            self.results_text.insert(tk.END, f"Frequency: Found {password_info['Frequency']} times in our database\n\n")

            # Get similar passwords
            similar_passwords = self.db.find_similar_passwords(password)
            if similar_passwords:
                self.results_text.insert(tk.END, "Similar passwords found:\n")
                for idx, p in enumerate(similar_passwords, 1):
                    self.results_text.insert(tk.END, f"{idx}. {p['Plaintext']} (found {p['Frequency']} times)\n")

            # Get benchmark information
            benchmarks = self.db.get_password_benchmarks(password_info['PasswordID'])
            if benchmarks:
                self.results_text.insert(tk.END, "\nEncryption Benchmarks:\n")
                for b in benchmarks:
                    self.results_text.insert(tk.END, f"- {b['Name']}: {b['Time']} seconds to crack\n")
        else:
            self.results_text.insert(tk.END, "Password not found in our breach database.\n\n")


        self.results_text.config(state=tk.DISABLED)

    def _load_recent_breaches(self):
        self.breach_listbox.delete(0, tk.END)
        self.breach_details_text.config(state=tk.NORMAL)
        self.breach_details_text.delete(1.0, tk.END)
        self.breach_details_text.config(state=tk.DISABLED)

        # Store breach IDs for later retrieval
        self.breach_ids = []

        if not hasattr(self, 'db') or not hasattr(self.db, 'cursor') or self.db.cursor is None:
            self.breach_listbox.insert(tk.END, "Database connection not available")
            return

        breaches = self.db.get_recent_breaches(10)
        if breaches:
            for breach in breaches:
                self.breach_listbox.insert(tk.END, f"{breach['Date']} - {breach['URL']}")
                self.breach_ids.append(breach['BreachID'])
        else:
            self.breach_listbox.insert(tk.END, "No breach data available")

    def _on_breach_selected(self, event):
        selection = self.breach_listbox.curselection()
        if not selection:
            return

        index = selection[0]

        if not hasattr(self, 'db') or not hasattr(self.db, 'cursor') or self.db.cursor is None:
            self.breach_details_text.config(state=tk.NORMAL)
            self.breach_details_text.delete(1.0, tk.END)
            self.breach_details_text.insert(tk.END, "Database connection not available")
            self.breach_details_text.config(state=tk.DISABLED)
            return

        if not hasattr(self, 'breach_ids') or index >= len(self.breach_ids):
            return

        breach_id = self.breach_ids[index]
        breach_details = self.db.get_breach_details(breach_id)

        self.breach_details_text.config(state=tk.NORMAL)
        self.breach_details_text.delete(1.0, tk.END)

        if breach_details:
            self.breach_details_text.insert(tk.END, f"Website: {breach_details['URL']}\n")
            self.breach_details_text.insert(tk.END, f"Date: {breach_details['Date']}\n")
            self.breach_details_text.insert(tk.END, f"Description: {breach_details['Description']}\n\n")

            if breach_details['AttackerDescription']:
                self.breach_details_text.insert(tk.END, f"Attacker: {breach_details['AttackerDescription']}\n")
                self.breach_details_text.insert(tk.END, f"Location: {breach_details['Location']}\n")
                self.breach_details_text.insert(tk.END, f"Methods: {breach_details['Methods']}\n\n")

            self.breach_details_text.insert(tk.END, f"Passwords exposed: {breach_details['password_count']}\n")
        else:
            self.breach_details_text.insert(tk.END, "No details available for this breach")

        self.breach_details_text.config(state=tk.DISABLED)

    def _load_encryption_methods(self):
        self.encryption_listbox.delete(0, tk.END)

        # Store encryption names for later retrieval
        self.encryption_names = []

        if not hasattr(self, 'db') or not hasattr(self.db, 'cursor') or self.db.cursor is None:
            self.encryption_listbox.insert(tk.END, "Database connection not available")
            return

        '''encryption_methods = self.db.get_encryption_methods()
        if encryption_methods:
            for method in encryption_methods:
                self.encryption_listbox.insert(tk.END, method['Name'])
                self.encryption_names.append(method['Name'])
        else:
            self.encryption_listbox.insert(tk.END, "No encryption methods available")
        '''
    def _on_encryption_selected(self, event):
        # Add this method to handle encryption method selection
        selection = self.encryption_listbox.curselection()
        if not selection or not hasattr(self, 'encryption_names'):
            return

        index = selection[0]
        if index >= len(self.encryption_names):
            return

        # Display information about the selected encryption method
        self.encryption_details_text.config(state=tk.NORMAL)
        self.encryption_details_text.delete(1.0, tk.END)

        if not hasattr(self, 'db') or not hasattr(self.db, 'cursor') or self.db.cursor is None:
            self.encryption_details_text.insert(tk.END, "Database connection not available")
        else:
            self.encryption_details_text.insert(tk.END, f"Details for {self.encryption_names[index]}")
            # Add more details from database if available

        self.encryption_details_text.config(state=tk.DISABLED)

    def _import_wordlist(self):
        if not hasattr(self, 'db') or not hasattr(self.db, 'cursor') or self.db.cursor is None:
            messagebox.showerror("Error", "Database connection is not available. Unable to import wordlist.")
            return

        file_path = filedialog.askopenfilename(
            title="Select Wordlist File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )

        if not file_path:
            return  # User canceled

        wordlist_name = os.path.basename(file_path)  # Use filename as wordlist name
        success = self.db.import_wordlist(wordlist_name, file_path)

        if success:
            messagebox.showinfo("Success", f"Successfully imported wordlist: {wordlist_name}")
        else:
            messagebox.showerror("Error", f"Failed to import wordlist: {wordlist_name}")

    def _on_close(self):
        # Close database connection before closing application
        if hasattr(self, 'db'):
            self.db.close_connection()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = BreachedPasswordsApp(root)
    root.mainloop()