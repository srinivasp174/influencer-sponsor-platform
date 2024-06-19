import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from app import app
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from models import db, User, Influencer, Sponsor, Campaign, Category, InfluencerCategory, SocialMedia
from functools import wraps

@app.context_processor
def inject_is_index():
    return {
        'is_index': request.path == '/',
        'is_login': request.path == '/login',
        'is_register': request.path == '/register',
        'is_influencer': '/influencer_profile' in request.path
    }

@app.context_processor
def inject_user():
    return {
        'logged_in': 'username' in session,
        'username': session.get('username')
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember_me')

        if not username or not password:
            flash('Please fill out all fields', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()
        if not user:
            flash('Username does not exist', 'danger')
            return redirect(url_for('login'))

        if not check_password_hash(user.passhash, password):
            flash('Incorrect password', 'danger')
            return redirect(url_for('login'))

        session['username'] = user.username
        session['usertype'] = user.usertype
        session['name'] = user.name
        session['email'] = user.email

        return redirect(url_for('influencer_profile', username=session['username']))
        
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        firstname = request.form.get("firstname")
        lastname = request.form.get("lastname")
        username = request.form.get("username")
        email = request.form.get("inputEmail")
        password = request.form.get("inputPassword")
        confirmpassword = request.form.get("confirmPassword")
        usertype = request.form.get('usertype')

        if not username or not email or not password or not confirmpassword or not usertype or not firstname or not lastname:
            flash('Please fill out all fields', 'danger')
            return redirect(url_for('register'))

        if password != confirmpassword:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))

        if len(password) < 8:
            flash('Password must be at least 8 characters', 'danger')
            return redirect(url_for('register'))

        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))

        mail = User.query.filter_by(email=email).first()
        if mail:
            flash('Email already exists', 'danger')
            return redirect(url_for('register'))

        name = f"{firstname} {lastname}"
        passhash = generate_password_hash(password)
        profile_pic = 'default_profile_pic.jpg'
        new_user = User(username=username, passhash=passhash, usertype=usertype, name=name, email=email, profile_pic=profile_pic)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

def auth_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please login to continue', 'danger')
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return decorated_function


@app.route('/logout')
@auth_required
def logout():
    session.pop('username')
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))


@app.route('/<username>')
@auth_required
def influencer_profile(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return render_template('influencer_profile.html', user=user)
    else:
        flash('User not found', 'danger')
        return redirect(url_for('index'))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/upload_profile_pic', methods=['POST'])
@auth_required
def upload_profile_pic():
    if 'profile_pic' not in request.files:
        flash('No profile picture uploaded', 'danger')
        return redirect(url_for('influencer_profile_edit'))

    file = request.files['profile_pic']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('influencer_profile_edit'))

    if file and allowed_file(file.filename):
        original_filename = secure_filename(file.filename)
        extension = original_filename.rsplit('.', 1)[1].lower()
        new_filename = f"user_{datetime.now().strftime('%Y%m%d%H%M%S')}.{extension}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        file.save(filepath)
        
        user = User.query.filter_by(username=session['username']).first()
        user.profile_pic = new_filename
        db.session.commit()
        
        flash('Profile picture uploaded successfully', 'success')
        return redirect(url_for('influencer_profile_edit', username=session['username']))
    
    else:
        flash('Invalid file type, only png, jpg, jpeg, and gif are allowed', 'danger')
        return redirect(url_for('influencer_profile_edit', username=session['username']))
    
@app.route('/settings/profile', methods=['GET', 'POST'])
@auth_required
def influencer_profile_edit():
    user = User.query.filter_by(username=session['username']).first()
    influencer = Influencer.query.filter_by(username=session['username']).first()

    if request.method == 'POST':
        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')
        email = request.form.get('email')
        bio = request.form.get('bio')

        if firstname:
            user.name = f"{firstname} {user.name.split(' ', 1)[1]}"
        if lastname:
            user.name = f"{user.name.split(' ', 1)[0]} {lastname}"
        if email:
            user.email = email
        if bio and influencer:
            influencer.bio = bio

        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('influencer_profile_edit'))

    if user:
        return render_template('influencer_profile_edit.html', user=user, influencer=influencer)
    else:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

    
@app.route('/settings/account')
@auth_required
def influencer_account_edit():
    user = User.query.filter_by(username=session['username']).first()
    if user:
        return render_template('influencer_account_edit.html', user=user)
    else:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))
    
@app.route('/settings/appearance')
@auth_required
def influencer_appearance_edit():
    user = User.query.filter_by(username=session['username']).first()
    if user:
        return render_template('influencer_appearance_edit.html', user=user)
    else:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))
    
@app.route('/settings/security')
@auth_required
def influencer_security_edit():
    user = User.query.filter_by(username=session['username']).first()
    if user:
        return render_template('influencer_security_edit.html', user=user)
    else:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))
    
@app.route('/settings/collaborations')
@auth_required
def influencer_collabs_edit():
    user = User.query.filter_by(username=session['username']).first()
    if user:
        return render_template('influencer_collabs_edit.html', user=user)
    else:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))