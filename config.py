import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-for-lab'
    DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'blog.db')