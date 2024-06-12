from flask import render_template, request, redirect, url_for, flash, session
from app import app
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Influencer, Sponsor, Campaign, Category, InfluencerCategory, SocialMedia


@app.context_processor
def inject_is_index():
    return {
        'is_index': request.path == '/',
        'is_login': request.path == '/login',
        'is_register': request.path == '/register',
        'is_influencer': request.path == '/influencer/profile'
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

        if user.usertype == 'influencer':
            return redirect(url_for('influencer_profile'))
        elif user.usertype == 'sponsor':
            return redirect(url_for('sponsor_profile'))
        
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
        new_user = User(username=username, passhash=passhash, usertype=usertype, name=name, email=email)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/influencer/profile')
def influencer_profile():
    return render_template('influencer_profile.html')