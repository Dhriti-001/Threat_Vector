import os
import sqlite3
from flask import g

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'threat_vector.db')

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def ensure_tables():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        full_name TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        password_hash TEXT DEFAULT ''
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        icon TEXT NOT NULL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS scenarios (
        id INTEGER PRIMARY KEY,
        category_code TEXT NOT NULL,
        channel TEXT NOT NULL DEFAULT 'email',
        title TEXT NOT NULL,
        sender TEXT NOT NULL,
        sender_name TEXT,
        subject TEXT,
        body TEXT NOT NULL,
        is_threat BOOLEAN NOT NULL,
        difficulty TEXT NOT NULL DEFAULT 'medium',
        red_flags TEXT NOT NULL,
        explanation TEXT NOT NULL,
        micro_lesson TEXT NOT NULL,
        FOREIGN KEY(category_code) REFERENCES categories(code)
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS user_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        scenario_id INTEGER NOT NULL,
        user_choice BOOLEAN NOT NULL,
        is_correct BOOLEAN NOT NULL,
        response_time_sec REAL NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(scenario_id) REFERENCES scenarios(id)
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS user_profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        composite_risk_score REAL DEFAULT 50.0,
        primary_weakness TEXT DEFAULT 'Baseline (Not yet evaluated)',
        category_stats TEXT DEFAULT '{}',
        total_tests INTEGER DEFAULT 0,
        accuracy_pct REAL DEFAULT 0.0,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    conn.commit()
    conn.close()

def init_db():
    ensure_tables()
