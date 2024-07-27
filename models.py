from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from app import db

# Association Tables
influencer_category = db.Table('influencer_category',
    db.Column('influencer_userid', db.Integer, db.ForeignKey('influencer.userid'), primary_key=True),
    db.Column('category_id', db.Integer, db.ForeignKey('category.categoryid'), primary_key=True)
)

sponsor_category = db.Table('sponsor_category',
    db.Column('sponsor_userid', db.Integer, db.ForeignKey('sponsor.userid'), primary_key=True),
    db.Column('category_id', db.Integer, db.ForeignKey('category.categoryid'), primary_key=True)
)

campaign_category = db.Table('campaign_category',
    db.Column('campaign_id', db.Integer, db.ForeignKey('campaign.campaignid'), primary_key=True),
    db.Column('category_id', db.Integer, db.ForeignKey('category.categoryid'), primary_key=True)
)

# Models
class User(db.Model):
    userid = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    passhash = db.Column(db.String(256), nullable=False)
    usertype = db.Column(db.String(32), nullable=False)
    name = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(32), nullable=False)
    profile_pic = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Added
    influencers = db.relationship('Influencer', backref='user', lazy=True, cascade="all, delete-orphan")
    sponsors = db.relationship('Sponsor', backref='user', lazy=True, cascade="all, delete-orphan")

class Influencer(db.Model):
    userid = db.Column(db.Integer, db.ForeignKey('user.userid'), primary_key=True)
    location = db.Column(db.String(32), nullable=True)
    demographic = db.Column(db.String(32), nullable=True)
    bio = db.Column(db.String(512), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Added
    campaigns = db.relationship('Campaign', backref='influencer', lazy=True, cascade="all, delete-orphan")
    socialmedia = db.relationship('SocialMedia', backref='influencer', lazy=True, cascade="all, delete-orphan")
    categories = db.relationship('Category', secondary=influencer_category, backref=db.backref('influencers', lazy='dynamic'))

class Sponsor(db.Model):
    userid = db.Column(db.Integer, db.ForeignKey('user.userid'), primary_key=True)
    location = db.Column(db.String(32), nullable=True)
    industry = db.Column(db.String(32), nullable=True)
    website = db.Column(db.String(32), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Added
    campaigns = db.relationship('Campaign', backref='sponsor', lazy=True, cascade="all, delete-orphan")
    categories = db.relationship('Category', secondary=sponsor_category, backref=db.backref('sponsors', lazy='dynamic'))

class Campaign(db.Model):
    campaignid = db.Column(db.Integer, primary_key=True)
    sponsor_userid = db.Column(db.Integer, db.ForeignKey('sponsor.userid'), nullable=True)
    influencer_userid = db.Column(db.Integer, db.ForeignKey('influencer.userid'), nullable=True)
    campaign_name = db.Column(db.String(32), nullable=False)
    campaign_description = db.Column(db.String(256), nullable=False)
    campaign_start = db.Column(db.DateTime, nullable=True)
    campaign_end = db.Column(db.DateTime, nullable=True)
    campaign_budget = db.Column(db.Integer, nullable=False)
    campaign_status = db.Column(db.String(32), nullable=False)
    campaign_duration = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Added
    categories = db.relationship('Category', secondary=campaign_category, backref=db.backref('campaigns', lazy='dynamic'))

class Category(db.Model):
    categoryid = db.Column(db.Integer, primary_key=True)
    category_name = db.Column(db.String(32), nullable=True)

class SocialMedia(db.Model):
    socialmediaid = db.Column(db.Integer, primary_key=True)
    influencer_userid = db.Column(db.Integer, db.ForeignKey('influencer.userid'), nullable=False)
    social_media_name = db.Column(db.String(32), nullable=False)
    social_media_link = db.Column(db.String(256), nullable=False)
    followers = db.Column(db.Integer, nullable=False)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reported_by = db.Column(db.Integer, db.ForeignKey('user.userid'), nullable=False)
    reported_user_id = db.Column(db.Integer, db.ForeignKey('user.userid'), nullable=False)
    reason = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='Pending')
