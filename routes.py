import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from app import app
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from models import db, User, Influencer, Sponsor, Campaign, Category, SocialMedia, influencer_category, Report
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
    
@app.context_processor
def inject_current_user():
    current_user = User.query.filter_by(username=session.get('username')).first()
    return dict(current_user=current_user)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember_me')

        if not identifier or not password:
            flash('Please fill out all fields', 'danger')
            return redirect(url_for('login'))

        if '@' in identifier:
            user = User.query.filter_by(email=identifier).first()
        else:
            user = User.query.filter_by(username=identifier).first()

        if not user:
            flash('User does not exist', 'danger')
            return redirect(url_for('login'))

        if not check_password_hash(user.passhash, password):
            flash('Incorrect password', 'danger')
            return redirect(url_for('login'))

        session['username'] = user.username
        session['usertype'] = user.usertype
        session['name'] = user.name
        session['email'] = user.email

        if user.usertype == 'admin':
            return redirect(url_for('admin_profile'))  # Redirect to admin profile if user is admin
        else:
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

        if usertype == 'influencer':
            influencer = Influencer(userid=new_user.userid)
            db.session.add(influencer)
        elif usertype == 'sponsor':
            sponsor = Sponsor(userid=new_user.userid)
            db.session.add(sponsor)
        db.session.commit()

        flash('User registered successfully', 'success')
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
        if user.usertype=='influencer':
            return render_template('influencer_profile.html', user=user)
        elif user.sponsors:
            return render_template('sponsor_profile.html', user=user)
        elif user.usertype=='admin':
            return render_template('admin_profile.html', user=user)
    flash('User not found', 'danger')
    return redirect(url_for('register'))


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
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

    influencer = Influencer.query.filter_by(userid=user.userid).first()

    if request.method == 'POST':
        try:
            firstname = request.form.get('firstname')
            lastname = request.form.get('lastname')
            email = request.form.get('email')
            bio = request.form.get('bio')
            location = request.form.get('location')

            if firstname and lastname:
                user.name = f"{firstname} {lastname}"
            if email:
                user.email = email
            if bio and influencer:
                influencer.bio = bio
            if location and influencer:
                influencer.location = location

            db.session.commit()
            flash('Profile updated successfully', 'success')
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while updating the profile.', 'danger')
        return redirect(url_for('influencer_profile_edit'))

    return render_template('influencer_profile_edit.html', user=user, influencer=influencer)    
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
    

@app.route('/campaign/create', methods=['GET', 'POST'])
@auth_required
def create_campaign():
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))
    sponsor = Sponsor.query.filter_by(userid=user.userid).first()
    if user.usertype == 'influencer':
        flash('You are not a Sponsor.', 'danger')
        return redirect(url_for('influencer_profile', username=session['username']))
    categories = Category.query.order_by(Category.category_name).all()
    if request.method == 'POST':
        name = request.form['name']
        description  = request.form['description']
        picture = None
        budget = request.form['budget']
        duration = request.form['duration']
        selected_categories = request.form.getlist('category[]')
        status = 'Created'

        new_campaign = Campaign(
            campaign_name=name,
            campaign_description=description,
            campaign_budget=budget,
            campaign_duration=duration,
            campaign_status=status,
            sponsor_userid=sponsor.userid
        )
        for category_id in selected_categories:
            category = Category.query.get(category_id)
            if category:
                new_campaign.categories.append(category)
        db.session.add(new_campaign)
        db.session.commit()
        flash('Campaign created successfully', 'success')
    return render_template('create_campaign.html', user=user, sponsor=sponsor, categories=categories)

@app.route('/campaign', methods=['GET'])
@auth_required
def view_campaigns():
    user = User.query.filter_by(username=session['username']).first()
    if user.usertype != 'influencer':
        flash('You are not an Influencer.', 'danger')
        return redirect(url_for('dashboard'))  # Adjust this redirect as necessary

    campaigns = Campaign.query.filter_by(campaign_status='Created').all()  # Show only 'Created' campaigns
    return render_template('view_campaigns.html', user=user, campaigns=campaigns)


@app.route('/campaign/<int:campaign_id>/apply', methods=['POST'])
@auth_required
def apply_campaign(campaign_id):
    user = User.query.filter_by(username=session['username']).first()
    if user.usertype != 'influencer':
        flash('You are not an Influencer.', 'danger')
        return redirect(url_for('dashboard'))  # Adjust this redirect as necessary

    influencer = Influencer.query.filter_by(userid=user.userid).first()
    campaign = Campaign.query.get_or_404(campaign_id)

    if campaign.influencer_userid is not None:
        flash('This campaign already has an influencer.', 'danger')
        return redirect(url_for('view_campaigns'))

    campaign.influencer_userid = influencer.userid
    db.session.commit()

    flash('Successfully applied for the campaign!', 'success')
    return redirect(url_for('view_campaigns'))

@app.route('/report/<int:user_id>', methods=['POST'])
@auth_required
def report_user(user_id):
    reported_user = User.query.get_or_404(user_id)
    user = User.query.filter_by(username=session.get('username')).first()
    
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('index'))
    
    reason = request.form.get('reason')
    if not reason:
        flash('Reason for reporting is required.', 'danger')
        return redirect(url_for('profile', user_id=user_id))  # Adjust this redirect as necessary

    report = Report(
        reported_by=user.username,
        reported_user_id=reported_user.userid,
        reason=reason
    )
    db.session.add(report)
    db.session.commit()
    
    flash('Report submitted successfully.', 'success')
    return redirect(url_for('influencer_profile', user_id=user_id))  # Adjust this redirect as necessary


@app.route('/admin/reports')
@auth_required
def view_reports():
    user = User.query.filter_by(username=session.get('username')).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('index'))
    if user.usertype != 'admin':
        flash('You do not have permission to view this page.', 'danger')
        return redirect(url_for('index'))
    reports = Report.query.all()
    return render_template('admin_reports.html', reports=reports)


@app.route('/admin/report/<int:report_id>/resolve', methods=['POST'])
@auth_required
def resolve_report(report_id):
    user = User.query.filter_by(username=session.get('username')).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('index'))
    if user.usertype != 'admin':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('index'))
    report = Report.query.get_or_404(report_id)
    report.status = 'Resolved'
    db.session.commit()
    flash('Report resolved successfully.', 'success')
    return redirect(url_for('view_reports'))

@app.route('/admin_profile')
@auth_required
def admin_profile():
    user = User.query.filter_by(username=session['username']).first()
    if user and user.usertype == 'admin':
        return render_template('admin_profile.html', user=user)
    else:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('index'))
