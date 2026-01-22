"""
SQLite state management for PIM owner sync.

This module tracks which users we have promoted to organization owner,
ensuring we only demote users that we promoted (stateful approach).
"""

import sqlite3
import logging
from typing import List, Dict, Optional


class PIMStateDB:
    """Manages the SQLite database for tracking promoted owners."""

    def __init__(self, db_path: str):
        """
        Initialize the PIM state database.

        :param db_path: Path to the SQLite database file.
        """
        self.db_path = db_path
        self.conn = None

    def connect(self):
        """Connect to the database and initialize schema."""
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
            self._init_schema()
            logging.debug(f'Connected to PIM state database: {self.db_path}')
        except Exception as e:
            logging.error(f'Failed to connect to PIM state database: {e}')
            raise

    def _init_schema(self):
        """Create the promoted_owners table if it doesn't exist."""
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS promoted_owners (
                github_login TEXT PRIMARY KEY,
                entra_id TEXT,
                email TEXT,
                display_name TEXT,
                promoted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.conn.commit()

    def save_promoted_user(self, github_login: str, entra_id: str,
                          email: str, display_name: str):
        """
        Save a promoted user to the database.

        :param github_login: GitHub username.
        :param entra_id: Entra ID user ID.
        :param email: User's email address.
        :param display_name: User's display name.
        """
        try:
            self.conn.execute('''
                INSERT OR REPLACE INTO promoted_owners
                (github_login, entra_id, email, display_name, promoted_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (github_login, entra_id, email, display_name))
            self.conn.commit()
            logging.debug(f'Saved promoted user to DB: {github_login}')
        except Exception as e:
            logging.error(f'Failed to save promoted user {github_login}: {e}')
            raise

    def get_promoted_users(self) -> List[Dict[str, str]]:
        """
        Get all users that we have promoted.

        :return: List of dictionaries with user details.
        """
        try:
            cursor = self.conn.execute(
                'SELECT github_login, entra_id, email, display_name, promoted_at '
                'FROM promoted_owners'
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except Exception as e:
            logging.error(f'Failed to get promoted users: {e}')
            raise

    def remove_promoted_user(self, github_login: str):
        """
        Remove a user from the promoted owners tracking.

        :param github_login: GitHub username to remove.
        """
        try:
            self.conn.execute(
                'DELETE FROM promoted_owners WHERE github_login = ?',
                (github_login,)
            )
            self.conn.commit()
            logging.debug(f'Removed promoted user from DB: {github_login}')
        except Exception as e:
            logging.error(f'Failed to remove promoted user {github_login}: {e}')
            raise

    def is_user_promoted(self, github_login: str) -> bool:
        """
        Check if a user is in our promoted owners tracking.

        :param github_login: GitHub username to check.
        :return: True if user is tracked as promoted.
        """
        try:
            cursor = self.conn.execute(
                'SELECT 1 FROM promoted_owners WHERE github_login = ? LIMIT 1',
                (github_login,)
            )
            return cursor.fetchone() is not None
        except Exception as e:
            logging.error(f'Failed to check if user {github_login} is promoted: {e}')
            raise

    def get_promoted_count(self) -> int:
        """
        Get the count of promoted users.

        :return: Number of users in the database.
        """
        try:
            cursor = self.conn.execute('SELECT COUNT(*) FROM promoted_owners')
            return cursor.fetchone()[0]
        except Exception as e:
            logging.error(f'Failed to get promoted user count: {e}')
            raise

    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()
            logging.debug('Closed PIM state database connection')
