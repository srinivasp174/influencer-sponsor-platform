from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from app import app
from flask_sqlalchemy import SQLAlchemy

db=SQLAlchemy(app)

class User(db.Model):
    userid = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    passhash = db.Column(db.String(256), nullable=False)
    usertype = db.Column(db.String(32), nullable=False)
    
    influencers = db.relationship('Influencer', backref='user', lazy=True)
    sponsors = db.relationship('Sponsor', backref='user', lazy=True)
    
class Influencer(db.Model):
    influencerid = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), db.ForeignKey('user.username'), nullable=False)
    first_name = db.Column(db.String(32), nullable=False)
    last_name = db.Column(db.String(32), nullable=False)
    email = db.Column(db.String(32), nullable=False)
    location = db.Column(db.String(32), nullable=False)
    demographic = db.Column(db.String(32), nullable=False)
    bio = db.Column(db.String(512), nullable=False)
    
    
    
class Sponsor(db.Model):
    sponsorid = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), db.ForeignKey('user.username'), nullable=False)
    company = db.Column(db.String(32), nullable=False)
    email = db.Column(db.String(32), nullable=False)
    location = db.Column(db.String(32), nullable=False)
    industry = db.Column(db.String(32), nullable=False)
    website = db.Column(db.String(32), nullable=False)
    
class Campaign(db.Model):
    campaignid = db.Column(db.Integer, primary_key=True)
    sponsorid = db.Column(db.Integer, db.ForeignKey('sponsor.sponsorid'), nullable=False)
    influencerid = db.Column(db.Integer, db.ForeignKey('influencer.influencerid'), nullable=False)
    campaign_name = db.Column(db.String(32), nullable=False)
    campaign_description = db.Column(db.String(256), nullable=False)
    campaign_start = db.Column(db.DateTime, nullable=False)
    campaign_end = db.Column(db.DateTime, nullable=False)
    campaign_budget = db.Column(db.Integer, nullable=False)
    campaign_status = db.Column(db.String(32), nullable=False)
    
    sponsor = db.relationship('Sponsor', backref='campaigns', lazy=True)
    influencer = db.relationship('Influencer', backref='campaigns', lazy=True)
    
class Category(db.Model):
    categoryid = db.Column(db.Integer, primary_key=True)
    category_name = db.Column(db.String(32), nullable=False)
    
    influencers = db.relationship('Influencer', secondary='influencer_category', backref='categories', lazy='dynamic')
    
class InfluencerCategory(db.Model):
    influencercategoryid = db.Column(db.Integer, primary_key=True)
    influencerid = db.Column(db.Integer, db.ForeignKey('influencer.influencerid'), nullable=False)
    categoryid = db.Column(db.Integer, db.ForeignKey('category.categoryid'), nullable=False)
    
    influencer = db.relationship('Influencer', backref='influencercategory', lazy=True)
    category = db.relationship('Category', backref='influencercategory', lazy=True)
    
class SocialMedia(db.Model):
    socialmediaid = db.Column(db.Integer, primary_key=True)
    influencerid = db.Column(db.Integer, db.ForeignKey('influencer.influencerid'), nullable=False)
    social_media_name = db.Column(db.String(32), nullable=False)
    social_media_link = db.Column(db.String(256), nullable=False)
    followers = db.Column(db.Integer, nullable=False)
    
    influencer = db.relationship('Influencer', backref='socialmedia', lazy=True)

with app.app_context():
    db.create_all()