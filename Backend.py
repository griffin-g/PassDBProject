import mysql.connector
from mysql.connector import Error
import os
from dotenv import load_dotenv

class BreachedPasswordsDB:
    def __init__(self):
        """Initialize database connection"""
        try:
            load_dotenv()  # Load environment variables from .env file

            self.connection = mysql.connector.connect(
                host=os.getenv("DB_HOST", "localhost"),
                user=os.getenv("DB_USER", "root"),
                password=os.getenv("DB_PASSWORD", "root"),
                database=os.getenv("DB_NAME", "breached_passwords")
            )

            if self.connection.is_connected():
                self.cursor = self.connection.cursor(dictionary=True)
                print("Database connection established successfully.")
            else:
                print("Failed to connect to the database.")
                self.cursor = None

        except Error as e:
            print(f"Error connecting to MySQL database: {e}")
            self.connection = None
            self.cursor = None

    def close_connection(self):
        if hasattr(self, 'connection') and self.connection and self.connection.is_connected():
            if hasattr(self, 'cursor') and self.cursor:
                self.cursor.close()
            self.connection.close()
            print("🔌 Database connection closed.")

    # Password-related methods
    # Check how many wordlists / breaches a password is in
    def check_password(self, plaintext_password):
        if not hasattr(self, 'cursor') or self.cursor is None:
            return None

        try:
            query = """
            """
            self.cursor.execute(query, (plaintext_password,))
            return self.cursor.fetchone()
        except Error as e:
            print(f"Error checking password: {e}")
            return None

    # TODO: find libraries or regex for password similarity
    # Find similar passwords to the entered password
    def find_similar_passwords(self, plaintext_password):
        if not hasattr(self, 'cursor') or self.cursor is None:
            return []
        '''try:
        except Error as e:
            print(f"Error finding similar passwords: {e}")
            return []'''

    def get_password_strength_metrics(self, password_id):
        if not hasattr(self, 'cursor') or self.cursor is None:
            return None

        try:
            query = """
            """
            self.cursor.execute(query, (password_id,))
            return self.cursor.fetchone()
        except Error as e:
            print(f"Error getting password strength metrics: {e}")
            return None

    # get info on breaches - all breach info, website url, attacker
    def get_recent_breaches(self, limit=5):
        """Get information about recent breaches"""
        if not hasattr(self, 'cursor') or self.cursor is None:
            return []

        try:
            query = """"""
            self.cursor.execute(query, (limit,))
            return self.cursor.fetchall()
        except Error as e:
            print(f"Error getting recent breaches: {e}")
            return []

    def get_breach_details(self, breach_id):
        """Get detailed information about a specific breach"""
        if not hasattr(self, 'cursor') or self.cursor is None:
            return None

        try:
            query = """"""
            self.cursor.execute(query, (breach_id,))
            return self.cursor.fetchone()
        except Error as e:
            print(f"Error getting breach details: {e}")
            return None

    # Encryption and benchmark methods
    def get_encryption_methods(self):
        if not hasattr(self, 'cursor') or self.cursor is None:
            return []

        try:
            query = "SELECT * FROM EncryptionMethod"
            self.cursor.execute(query)
            return self.cursor.fetchall()
        except Error as e:
            print(f"Error getting encryption methods: {e}")
            return []

    def get_password_benchmarks(self, password_id):
        """Get benchmarks for a specific password"""
        if not hasattr(self, 'cursor') or self.cursor is None:
            return []

        try:
            query = """"""
            self.cursor.execute(query, (password_id,))
            return self.cursor.fetchall()
        except Error as e:
            print(f"Error getting password benchmarks: {e}")
            return []

    # Data insertion methods
    def add_password(self, plaintext, strength=None):
        """Add a new password to the database"""
        if not hasattr(self, 'cursor') or self.cursor is None:
            return None

        try:
            query = """
            INSERT INTO Password (Plaintext, Strength, Frequency)
            VALUES (%s, %s, 1)
            ON DUPLICATE KEY UPDATE Frequency = Frequency + 1
            """
            self.cursor.execute(query, (plaintext, strength))
            self.connection.commit()
            return self.cursor.lastrowid
        except Error as e:
            print(f"Error adding password: {e}")
            return None

    def add_breach(self, attacker_id, website_url, description, breach_date):
        """Add a new breach to the database"""
        if not hasattr(self, 'cursor') or self.cursor is None:
            return None

        try:
            query = """
            INSERT INTO Breach (AttackerID, WebsiteURL, Description, Date)
            VALUES (%s, %s, %s, %s)
            """
            self.cursor.execute(query, (attacker_id, website_url, description, breach_date))
            self.connection.commit()
            return self.cursor.lastrowid
        except Error as e:
            print(f"Error adding breach: {e}")
            return None

    def associate_password_with_breach(self, password_id, breach_id):
        """Create a relationship between a password and a breach"""
        if not hasattr(self, 'cursor') or self.cursor is None:
            return False

        try:
            query = """
            INSERT INTO PasswordToBreach (PasswordID, BreachID)
            VALUES (%s, %s)
            """
            self.cursor.execute(query, (password_id, breach_id))
            self.connection.commit()
            return True
        except Error as e:
            print(f"Error associating password with breach: {e}")
            return False

    def import_wordlist(self, wordlist_name, file_path):
        """Import passwords from a wordlist, analyze their strength, and store them in the database."""
        if not hasattr(self, 'cursor') or self.cursor is None:
            print("Database connection is not available. Unable to import wordlist.")
            return False

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                passwords = [line.strip() for line in f if line.strip()]

            if not passwords:
                print("Wordlist is empty.")
                return False

            # Add wordlist entry
            try:
                query = """
                INSERT INTO Wordlist (Name, Source, Size)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE Size = Size + %s
                """
                self.cursor.execute(query, (wordlist_name, file_path, len(passwords), len(passwords)))
                self.connection.commit()
                wordlist_id = self.cursor.lastrowid
            except Error as e:
                print(f"Error adding wordlist: {e}")
                return False

            # Insert passwords and analyze strength
            success_count = 0
            for password in passwords:
                try:
                    # Simple strength calculation based on length and character types
                    strength_score = min(len(password) / 2, 10)  # Simple placeholder

                    query = """
                    INSERT INTO Password (Plaintext, Strength, Frequency)
                    VALUES (%s, %s, 1)
                    ON DUPLICATE KEY UPDATE Frequency = Frequency + 1
                    """
                    self.cursor.execute(query, (password, strength_score))
                    self.connection.commit()
                    password_id = self.cursor.lastrowid

                    # Link password to wordlist
                    self.cursor.execute(
                        "INSERT IGNORE INTO PasswordToWordlist (PasswordID, WordlistID) VALUES (%s, %s)",
                        (password_id, wordlist_id),
                    )
                    self.connection.commit()
                    success_count += 1
                except Error as e:
                    print(f"Error importing password '{password}': {e}")
                    continue

            print(f"Successfully imported {success_count} out of {len(passwords)} passwords from {wordlist_name}.")
            return True
        except Exception as e:
            print(f"Error importing wordlist: {e}")
            return False