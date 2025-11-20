import sqlite3
from werkzeug.security import generate_password_hash
from config import Config


def init_db():
    """Инициализация базы данных"""
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            avatar TEXT DEFAULT 'default.png',
            timezone_offset INTEGER DEFAULT 3
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NULL,
            FOREIGN KEY (author_id) REFERENCES users (id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            post_id INTEGER NOT NULL,
            author_name TEXT DEFAULT 'Гость',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (post_id) REFERENCES posts (id)
        )
    ''')

    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        admin_pass = generate_password_hash('admin123')
        cursor.execute(
            "INSERT INTO users (username, password_hash, avatar, timezone_offset) VALUES (?, ?, 'default.png', 3)",
            ('admin', admin_pass))

    conn.commit()
    conn.close()


def get_db_connection():
    """Получение соединения с базой данных"""
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn
