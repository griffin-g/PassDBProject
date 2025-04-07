import mysql.connector
from mysql.connector import Error
import os
from dotenv import load_dotenv
import re
import hashlib
import math
import bcrypt
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class BreachedPasswordsDB:
    def __init__(self):
        """Initialize database connection"""
        load_dotenv()

        try:
            self.connection = mysql.connector.connect(
                host=os.getenv("DB_HOST", "localhost"),
                user=os.getenv("DB_USER", "root"),
                password=os.getenv("DB_PASSWORD", "root"),
                database=os.getenv("DB_NAME", "breached_passwords")
            )

            if self.connection.is_connected():
                self.cursor = self.connection.cursor(dictionary=True)
                logging.info("Database connection established successfully.")
            else:
                logging.error("Failed to connect to the database.")
                self.cursor = None

        except Error as e:
            logging.error(f"Database connection error: {e}")
            self.connection = None

    def close_connection(self):
        """Close the database connection properly"""
        if self.cursor:
            self.cursor.close()
        if self.connection and self.connection.is_connected():
            self.connection.close()
            logging.info("Database connection closed.")

    def execute_query(self, query, params=None):
        try:
            with self.connection.cursor(dictionary=True) as cursor:
                cursor.execute(query, params)
                self.connection.commit()
                return cursor.fetchall()
        except Error as e:
            logging.error(f"Database query error: {e}")
            return None

    def add_user(self, username, role, email, password):
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        query = """
        INSERT INTO User (Username, Role, Email, PasswordHash)
        VALUES (%s, %s, %s, %s)
        """
        params = (username, role, email, hashed_password)
        return self.execute_query(query, params)

    def get_user_by_username(self, username):
        query = "SELECT * FROM User WHERE Username = %s"
        return self.execute_query(query, (username,))

    """Verifying a user's password"""
    def verify_password(self, username, password):
        user = self.get_user_by_username(username)
        if user and bcrypt.checkpw(password.encode(), user[0]['PasswordHash'].encode()):
            return True
        return False

    """Checking for a wordlist password"""
    def check_password(self, plaintext_password):
        if not self.connection or not self.connection.is_connected():
            logging.error("Database connection is not available.")
            return None

        query = """
        SELECT 
            p.PasswordID, 
            p.Plaintext, 
            p.Strength, 
            p.Frequency,
            COUNT(DISTINCT ptb.BreachID) as breach_count,
            COUNT(DISTINCT ptw.WordlistID) as wordlist_count
        FROM Password p
        LEFT JOIN PasswordToBreach ptb ON p.PasswordID = ptb.PasswordID
        LEFT JOIN PasswordToWordlist ptw ON p.PasswordID = ptw.PasswordID
        WHERE p.Plaintext = %s
        GROUP BY p.PasswordID, p.Plaintext, p.Strength, p.Frequency
        """
        try:
            with self.connection.cursor(dictionary=True) as cursor:
                cursor.execute(query, (plaintext_password,))
                return cursor.fetchone()
        except Error as e:
            logging.error(f"Error checking password: {e}")
            return None

    def calculate_password_strength(self, password):
        """Calculate password strength based on: Length, Uppercase, Lowercase, Contains Digits, Contains Special characters."""
        if not password:
            return 0

        score = 0

        # Length (0-5 points)
        length_scores = {12: 5, 10: 4, 8: 3, 6: 2}
        score += next((v for k, v in length_scores.items() if len(password) >= k), 1)

        # Characters (0-5 points)
        score += sum([
            bool(re.search(r'[A-Z]', password)),  # Uppercase
            bool(re.search(r'[a-z]', password)),  # Lowercase
            bool(re.search(r'[0-9]', password)),  # Digits
            2 * bool(re.search(r'[^A-Za-z0-9]', password))  # Special chars (2 points)
        ])

        return min(score, 10)

    def find_similar_passwords(self, plaintext_password):
        if not self.connection or not self.connection.is_connected():
            logging.error("Database connection is not available.")
            return []

        try:
            similar_passwords = []
            with self.connection.cursor(dictionary=True) as cursor:
                # 1. Find passwords with the same prefix (first 3 chars)
                if len(plaintext_password) >= 3:
                    prefix = plaintext_password[:3]
                    query = """
                    SELECT PasswordID, Plaintext, Frequency 
                    FROM Password 
                    WHERE Plaintext LIKE %s AND Plaintext != %s 
                    ORDER BY Frequency DESC
                    LIMIT 10
                    """
                    cursor.execute(query, (prefix + '%', plaintext_password))
                    similar_passwords = cursor.fetchall()

                # 2. If no results, find passwords with a similar length
                if not similar_passwords:
                    min_len, max_len = max(3, len(plaintext_password) - 2), len(plaintext_password) + 2
                    query = """
                    SELECT PasswordID, Plaintext, Frequency 
                    FROM Password 
                    WHERE LENGTH(Plaintext) BETWEEN %s AND %s
                    ORDER BY Frequency DESC
                    LIMIT 10
                    """
                    cursor.execute(query, (min_len, max_len))
                    similar_passwords = cursor.fetchall()

            return similar_passwords

        except Error as e:
            logging.error(f"Error finding similar passwords: {e}")
            return []

    def get_password_strength_metrics(self, password_id):
        if not self.connection or not self.connection.is_connected():
            logging.error("Database connection is not available.")
            return None

        query = """
        SELECT 
            p.PasswordID,
            p.Plaintext,
            p.Strength,
            p.Frequency,
            COUNT(DISTINCT ptb.BreachID) as breach_count,
            COUNT(DISTINCT ptw.WordlistID) as wordlist_count,
            GROUP_CONCAT(DISTINCT w.Name) as found_in_wordlists
        FROM Password p
        LEFT JOIN PasswordToBreach ptb ON p.PasswordID = ptb.PasswordID
        LEFT JOIN PasswordToWordlist ptw ON p.PasswordID = ptw.PasswordID
        LEFT JOIN Wordlist w ON ptw.WordlistID = w.WordlistID
        WHERE p.PasswordID = %s
        GROUP BY p.PasswordID, p.Plaintext, p.Strength, p.Frequency
        """
        try:
            with self.connection.cursor(dictionary=True) as cursor:
                cursor.execute(query, (password_id,))
                return cursor.fetchone()
        except Error as e:
            logging.error(f"Error getting password strength metrics: {e}")
            return None

    def get_recent_breaches(self, limit=5):
        """Retrieve information about the most recent breaches."""
        if not self.connection or not self.connection.is_connected():
            logging.error("Database connection is not available.")
            return []

        query = """
           SELECT 
               b.BreachID,
               b.Date,
               w.URL,
               b.Description,
               COUNT(DISTINCT ptb.PasswordID) AS password_count
           FROM Breach b
           JOIN Website w ON b.WebsiteURL = w.URL
           LEFT JOIN PasswordToBreach ptb ON b.BreachID = ptb.BreachID
           GROUP BY b.BreachID, b.Date, w.URL, b.Description
           ORDER BY b.Date DESC
           LIMIT %s
           """

        try:
            with self.connection.cursor(dictionary=True) as cursor:
                cursor.execute(query, (limit,))
                return cursor.fetchall()
        except Error as e:
            logging.error(f"Error retrieving recent breaches: {e}")
            return []

    def get_breach_details(self, breach_id):
        """Retrieve detailed information about a specific breach."""
        if not self.connection or not self.connection.is_connected():
            logging.error("Database connection is not available.")
            return None

        query = """
           SELECT 
               b.BreachID,
               b.Date,
               w.URL,
               w.Description AS WebsiteDescription,
               b.Description,
               a.Description AS AttackerDescription,
               a.Location,
               a.Methods,
               COUNT(DISTINCT ptb.PasswordID) AS password_count
           FROM Breach b
           JOIN Website w ON b.WebsiteURL = w.URL
           LEFT JOIN Attacker a ON b.AttackerID = a.AttackerID
           LEFT JOIN PasswordToBreach ptb ON b.BreachID = ptb.BreachID
           WHERE b.BreachID = %s
           GROUP BY b.BreachID, b.Date, w.URL, w.Description, b.Description, 
                    a.Description, a.Location, a.Methods
           """

        try:
            with self.connection.cursor(dictionary=True) as cursor:
                cursor.execute(query, (breach_id,))
                return cursor.fetchone()
        except Error as e:
            logging.error(f"Error retrieving breach details: {e}")
            return None

    def get_password_benchmarks(self, password_id):
        """Retrieve benchmark results for a specific password."""
        if not self.connection or not self.connection.is_connected():
            logging.error("Database connection is not available.")
            return []

        query = """
           SELECT 
               pb.PwBenchmarkID,
               pb.PasswordID,
               pb.Encryption_Name AS Name,
               pb.Time,
               pb.Success,
               em.Description
           FROM PasswordBenchmark pb
           JOIN EncryptionMethod em ON pb.Encryption_Name = em.Name
           WHERE pb.PasswordID = %s
           ORDER BY pb.Time ASC
           """

        try:
            with self.connection.cursor(dictionary=True) as cursor:
                cursor.execute(query, (password_id,))
                return cursor.fetchall()
        except Error as e:
            logging.error(f"Error retrieving password benchmarks: {e}")
            return []

    def get_all_wordlists(self):
        """Get a list of all wordlists in the database"""
        if not self.connection or not self.connection.is_connected():
            logging.error("Database connection is not available.")
            return []

        query = """
          SELECT 
              WordlistID, 
              Name, 
              Source, 
              Size, 
              DateAdded,
              (SELECT COUNT(DISTINCT PasswordID) FROM PasswordToWordlist WHERE WordlistID = w.WordlistID) as password_count
          FROM 
              Wordlist w
          ORDER BY 
              DateAdded DESC
          """

        try:
            with self.connection.cursor(dictionary=True) as cursor:
                cursor.execute(query)
                return cursor.fetchall()
        except Error as e:
            logging.error(f"Error getting wordlists: {e}")
            return []

    def get_wordlist_details(self, wordlist_id):
        """Get detailed information about a specific wordlist"""
        if not self.connection or not self.connection.is_connected():
            logging.error("Database connection is not available.")
            return None

        query = """
          SELECT 
              w.WordlistID,
              w.Name,
              w.Source,
              w.Size,
              w.DateAdded,
              COUNT(DISTINCT ptw.PasswordID) as password_count,
              AVG(p.Strength) as avg_strength,
              MIN(p.Strength) as min_strength,
              MAX(p.Strength) as max_strength
          FROM 
              Wordlist w
              LEFT JOIN PasswordToWordlist ptw ON w.WordlistID = ptw.WordlistID
              LEFT JOIN Password p ON ptw.PasswordID = p.PasswordID
          WHERE 
              w.WordlistID = %s
          GROUP BY 
              w.WordlistID, w.Name, w.Source, w.Size, w.DateAdded
          """

        try:
            with self.connection.cursor(dictionary=True) as cursor:
                cursor.execute(query, (wordlist_id,))
                return cursor.fetchone()
        except Error as e:
            logging.error(f"Error getting wordlist details: {e}")
            return None

    def get_passwords_in_wordlist(self, wordlist_id, limit=100, offset=0):
        """Get passwords that are in a specific wordlist"""
        if not self.connection or not self.connection.is_connected():
            logging.error("Database connection is not available.")
            return []

        query = """
          SELECT 
              p.PasswordID,
              p.Plaintext,
              p.Strength,
              p.Frequency
          FROM 
              Password p
              JOIN PasswordToWordlist ptw ON p.PasswordID = ptw.PasswordID
          WHERE 
              ptw.WordlistID = %s
          ORDER BY 
              p.Frequency DESC
          LIMIT %s OFFSET %s
          """

        try:
            with self.connection.cursor(dictionary=True) as cursor:
                cursor.execute(query, (wordlist_id, limit, offset))
                return cursor.fetchall()
        except Error as e:
            logging.error(f"Error getting passwords in wordlist: {e}")
            return []

    def analyze_wordlist_statistics(self, wordlist_id):
        """Analyze statistics about passwords in a wordlist"""
        if not self.connection or not self.connection.is_connected():
            logging.error("Database connection is not available.")
            return None

        query = """
          SELECT 
              AVG(LENGTH(p.Plaintext)) as avg_length,
              MIN(LENGTH(p.Plaintext)) as min_length,
              MAX(LENGTH(p.Plaintext)) as max_length,
              COUNT(CASE WHEN p.Plaintext REGEXP '[0-9]' THEN 1 END) / COUNT(*) * 100 as pct_with_numbers,
              COUNT(CASE WHEN p.Plaintext REGEXP '[A-Z]' THEN 1 END) / COUNT(*) * 100 as pct_with_uppercase,
              COUNT(CASE WHEN p.Plaintext REGEXP '[^A-Za-z0-9]' THEN 1 END) / COUNT(*) * 100 as pct_with_special_chars
          FROM 
              Password p
              JOIN PasswordToWordlist ptw ON p.PasswordID = ptw.PasswordID
          WHERE 
              ptw.WordlistID = %s
          """

        try:
            with self.connection.cursor(dictionary=True) as cursor:
                cursor.execute(query, (wordlist_id,))
                return cursor.fetchone()
        except Error as e:
            logging.error(f"Error analyzing wordlist statistics: {e}")
            return None

    def add_encryption_method(self, name, description):
        """Add a new encryption method to the database"""
        if not self.connection or not self.connection.is_connected():
            logging.error("Database connection is not available.")
            return False

        query = """
          INSERT INTO EncryptionMethod (Name, Description)
          VALUES (%s, %s)
          """

        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, (name, description))
                self.connection.commit()
            return True
        except Error as e:
            logging.error(f"Error adding encryption method: {e}")
            return False

    def add_password_benchmark(self, password_id, encryption_name, time_taken, success):
        """Add a new password benchmark to the database"""
        if not self.connection or not self.connection.is_connected():
            logging.error("Database connection is not available.")
            return False

        query = """
          INSERT INTO PasswordBenchmark (PasswordID, Encryption_Name, Time, Success)
          VALUES (%s, %s, %s, %s)
          """

        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, (password_id, encryption_name, time_taken, success))
                self.connection.commit()
            return True
        except Error as e:
            logging.error(f"Error adding password benchmark: {e}")
            return False

    def add_website(self, url, description):
        """Add a new website to the database"""
        if not self.connection or not self.connection.is_connected():
            logging.error("Database connection is not available.")
            return False

        query = """
          INSERT INTO Website (URL, Description) 
          VALUES (%s, %s)
          ON DUPLICATE KEY UPDATE Description = %s
          """

        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, (url, description, description))
                self.connection.commit()
            return True
        except Error as e:
            logging.error(f"Error adding website: {e}")
            return False

    def add_attacker(self, description, location, methods):
        """Add a new attacker to the database"""
        if not self.connection or not self.connection.is_connected():
            logging.error("Database connection is not available.")
            return None

        query = """
          INSERT INTO Attacker (Description, Location, Methods)
          VALUES (%s, %s, %s)
          """

        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, (description, location, methods))
                self.connection.commit()
            return cursor.lastrowid
        except Error as e:
            logging.error(f"Error adding attacker: {e}")
            return None

    def get_password_from_hash(self, hash_value, hash_type='md5'):
        """Look for a password that matches the provided hash"""
        if not self.connection or not self.connection.is_connected():
            logging.error("Database connection is not available.")
            return None

        try:
            query = """
              SELECT PasswordID, Plaintext FROM Password
              """

            with self.connection.cursor(dictionary=True) as cursor:
                cursor.execute(query)
                passwords = cursor.fetchall()

            # Check each password to see if its hash matches
            for password in passwords:
                plaintext = password['Plaintext']

                # Generate hash based on the specified hash type
                if hash_type.lower() == 'md5':
                    generated_hash = hashlib.md5(plaintext.encode()).hexdigest()
                elif hash_type.lower() == 'sha1':
                    generated_hash = hashlib.sha1(plaintext.encode()).hexdigest()
                elif hash_type.lower() == 'sha256':
                    generated_hash = hashlib.sha256(plaintext.encode()).hexdigest()
                else:
                    return None  # Unsupported hash type

                # If we found a match, return the password
                if generated_hash == hash_value.lower():
                    return password

            return None  # No match found
        except Error as e:
            logging.error(f"Error looking up hash: {e}")
            return None


    def generate_wordlist_summary(self):
        """Generate a summary of all wordlists in the database"""
        if not self.connection or not self.connection.is_connected():
            logging.error("Database connection is not available.")
            return None

        try:
            query = """
            SELECT
                COUNT(DISTINCT w.WordlistID) as total_wordlists,
                SUM(w.Size) as total_entries,
                COUNT(DISTINCT p.PasswordID) as unique_passwords,
                AVG(p.Strength) as avg_strength
            FROM
                Wordlist w
                LEFT JOIN PasswordToWordlist ptw ON w.WordlistID = ptw.WordlistID
                LEFT JOIN Password p ON ptw.PasswordID = p.PasswordID
            """
            with self.connection.cursor(dictionary=True) as cursor:
                cursor.execute(query)
                return cursor.fetchone()
        except Error as e:
            logging.error(f"Error generating wordlist summary: {e}")
            return None

    def search_passwords(self, search_term, limit=100):
        """Search for passwords containing a specific pattern"""
        if not self.connection or not self.connection.is_connected():
            logging.error("Database connection is not available.")
            return []

        try:
            query = """
            SELECT
                PasswordID,
                Plaintext,
                Strength,
                Frequency
            FROM
                Password
            WHERE
                Plaintext LIKE %s
            ORDER BY
                Frequency DESC
            LIMIT %s
            """
            with self.connection.cursor(dictionary=True) as cursor:
                cursor.execute(query, (f'%{search_term}%', limit))
                return cursor.fetchall()
        except Error as e:
            logging.error(f"Error searching passwords: {e}")
            return []

    def get_password_distribution(self):
        """Get distribution of passwords by strength category"""
        if not self.connection or not self.connection.is_connected():
            logging.error("Database connection is not available.")
            return []

        try:
            query = """
            SELECT
                CASE
                    WHEN Strength < 3 THEN 'Very Weak (0-2)'
                    WHEN Strength < 5 THEN 'Weak (3-4)'
                    WHEN Strength < 7 THEN 'Moderate (5-6)'
                    WHEN Strength < 9 THEN 'Strong (7-8)'
                    ELSE 'Very Strong (9-10)'
                END as strength_category,
                COUNT(*) as password_count,
                AVG(LENGTH(Plaintext)) as avg_length
            FROM
                Password
            GROUP BY
                strength_category
            ORDER BY
                MIN(Strength)
            """
            with self.connection.cursor(dictionary=True) as cursor:
                cursor.execute(query)
                return cursor.fetchall()
        except Error as e:
            logging.error(f"Error getting password distribution: {e}")
            return []

    def import_wordlist(self, wordlist_name, file_path):
        """Import passwords from a wordlist, analyze their strength, and store them in the database."""
        if not self.connection or not self.connection.is_connected():
            logging.error("Database connection is not available. Unable to import wordlist.")
            return False

        try:
            # Open the file and read the wordlist into memory
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                passwords = [line.strip() for line in f if line.strip()]  # Strip any empty or unwanted lines

            if not passwords:
                logging.error("Wordlist is empty.")
                return False

            # Add wordlist entry to the database
            try:
                query = """
                INSERT INTO Wordlist (Name, Source, Size)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE Size = %s
                """
                with self.connection.cursor() as cursor:
                    cursor.execute(query, (wordlist_name, file_path, len(passwords), len(passwords)))
                    self.connection.commit()
                    wordlist_id = cursor.lastrowid

                    if not wordlist_id:
                        # If we're updating an existing wordlist, get its ID
                        cursor.execute("SELECT WordlistID FROM Wordlist WHERE Name = %s", (wordlist_name,))
                        result = cursor.fetchone()  # result will be a tuple
                        if result:
                            wordlist_id = result[0]  # Access tuple by index (first element)
                        else:
                            logging.error("Failed to get wordlist ID.")
                            return False

            except Error as e:
                logging.error(f"Error adding wordlist: {e}")
                return False

            # Insert passwords and analyze their strength
            success_count = 0
            batch_size = 1000
            current_batch = []

            for password in passwords:
                try:
                    # Calculate strength score using your method
                    strength_score = self.calculate_password_strength(password)

                    current_batch.append((password, strength_score))

                    # When batch reaches size or it's the last password, execute insert
                    if len(current_batch) >= batch_size or password == passwords[-1]:
                        # Insert passwords in batch
                        password_ids = {}
                        for passwd, strength in current_batch:
                            # Check if password already exists
                            with self.connection.cursor() as cursor:
                                cursor.execute(
                                    "SELECT PasswordID FROM Password WHERE Plaintext = %s", (passwd,)
                                )
                                result = cursor.fetchone()

                                if result:
                                    # Password exists - increment
                                    password_id = result[0]  # Access tuple by index
                                    with self.connection.cursor() as cursor:
                                        cursor.execute(
                                            "UPDATE Password SET Frequency = Frequency + 1 WHERE PasswordID = %s",
                                            (password_id,)
                                        )
                                else:
                                    # New password - insert it
                                    with self.connection.cursor() as cursor:
                                        cursor.execute(
                                            "INSERT INTO Password (Plaintext, Strength, Frequency) VALUES (%s, %s, 1)",
                                            (passwd, strength)
                                        )
                                        password_id = cursor.lastrowid

                                password_ids[passwd] = password_id

                        self.connection.commit()

                        link_batch = []
                        for passwd in password_ids:
                            link_batch.append((password_ids[passwd], wordlist_id))

                        if link_batch:
                            with self.connection.cursor() as cursor:
                                cursor.executemany(
                                    "INSERT IGNORE INTO PasswordToWordlist (PasswordID, WordlistID) VALUES (%s, %s)",
                                    link_batch
                                )
                            self.connection.commit()

                        success_count += len(current_batch)
                        current_batch = []

                except Error as e:
                    logging.error(f"Error importing password batch: {e}")
                    continue

            logging.info(
                f"Successfully imported {success_count} out of {len(passwords)} passwords from {wordlist_name}.")
            return True
        except Exception as e:
            logging.error(f"Error importing wordlist: {e}")
            return False