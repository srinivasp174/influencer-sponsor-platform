import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI')
    SQLALCHEMY_TRACK_MODIFICATIONS = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS').lower() in ['true', '1', 't']
    UPLOAD_FOLDER = 'static/profile_pic'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}