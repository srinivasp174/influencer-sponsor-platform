import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify,  abort, send_from_directory
from app import app
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from models import db, User, Influencer, Sponsor, Campaign, Category, influencer_category, Report, InfluencerRequest
from functools import wraps
from sqlalchemy import func
from random import shuffle


@app.context_processor
def inject_is_index():
    return {
        'is_index': request.path == '/',
        'is_login': request.path == '/login',
        'is_register': request.path == '/register',
        'is_about' : request.path == '/about',
        'is_pricing' : request.path == '/pricing',
        'is_privacy_policy' : request.path == '/privacy_policy',
        'is_terms' : request.path == '/terms',
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
    current_user = None
    if 'username' in session:
        current_user = User.query.filter_by(username=session.get('username')).first()
    return dict(current_user=current_user)

def get_current_user():
    if 'username' in session:
        return User.query.filter_by(username=session.get('username')).first()
    return None


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

        user = User.query.filter_by(email=identifier).first() if '@' in identifier else User.query.filter_by(username=identifier).first()

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

        user.usertype = 'influencer' if user.usertype == 'influencer' else 'sponsor' if user.usertype == 'sponsor' else 'admin' if user.usertype == 'admin' else 'unknown'
        
        return redirect(url_for('user_profile', username=user.username))

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

        if not all([username, email, password, confirmpassword, usertype, firstname, lastname]):
            flash('Please fill out all fields', 'danger')
            return redirect(url_for('register'))

        if password != confirmpassword:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))

        if len(password) < 8:
            flash('Password must be at least 8 characters', 'danger')
            return redirect(url_for('register'))

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or Email already exists', 'danger')
            return redirect(url_for('register'))

        name = f"{firstname} {lastname}"
        passhash = generate_password_hash(password)
        profile_pic = 'default_profile_pic.jpg'
        new_user = User(username=username, passhash=passhash, usertype=usertype, name=name, email=email, profile_pic=profile_pic)
        db.session.add(new_user)
        db.session.commit()

        if usertype == 'influencer':
            db.session.add(Influencer(userid=new_user.userid))
        elif usertype == 'sponsor':
            db.session.add(Sponsor(userid=new_user.userid))
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
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/<username>')
@auth_required
def user_profile(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('index'))

    profile_type = user.usertype if user.usertype in ['influencer', 'sponsor', 'admin'] else None
    if not profile_type:
        flash('Unknown usertype', 'danger')
        return redirect(url_for('index'))

    current_user = get_current_user()  

    campaigns = []
    requests = []
    if profile_type == 'influencer' and user.username == current_user.username:
        campaigns = Campaign.query.filter_by(influencer_userid=user.userid).all()
        requests = InfluencerRequest.query.filter_by(influencer_id=user.userid).all()
    elif profile_type == 'sponsor' and user.username == current_user.username:
        campaigns = Campaign.query.filter_by(sponsor_userid=user.userid).all()

    return render_template('user_profile.html', user=user, profile_type=profile_type, campaigns=campaigns, requests=requests)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/upload_profile_pic', methods=['POST'])
@auth_required
def upload_profile_pic():
    if 'profile_pic' not in request.files:
        flash('No profile picture uploaded', 'danger')
        return redirect(url_for('user_profile_edit'))

    file = request.files['profile_pic']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('user_profile_edit'))

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
        return redirect(url_for('user_profile_edit', username=session['username']))
    
    flash('Invalid file type, only png, jpg, jpeg, and gif are allowed', 'danger')
    return redirect(url_for('user_profile_edit', username=session['username']))

@app.route('/edit_profile', methods=['GET', 'POST'])
@auth_required
def user_profile_edit():
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

    influencer = Influencer.query.filter_by(userid=user.userid).first()

    if request.method == 'POST':
        try:
            firstname = request.form.get('firstname')
            lastname = request.form.get('lastname')
            username = request.form.get('username')
            email = request.form.get('email')
            bio = request.form.get('bio')
            location = request.form.get('location')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            user.twitter = request.form.get('twitter')
            user.facebook = request.form.get('facebook')
            user.instagram = request.form.get('instagram')
            user.linkedin = request.form.get('linkedin')

            if firstname and lastname:
                user.name = f"{firstname} {lastname}"
            if username:
                user.username = username
                session['username'] = username
            if email:
                user.email = email
            if bio and influencer:
                influencer.bio = bio
            if location and influencer:
                influencer.location = location
            if password and confirm_password:
                if password == confirm_password:
                    user.passhash = generate_password_hash(password)
                else:
                    flash('Passwords do not match', 'danger')
                    return redirect(url_for('user_profile_edit'))

            db.session.commit()
            flash('Profile updated successfully', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while updating the profile: {str(e)}', 'danger')
        return redirect(url_for('user_profile_edit'))

    return render_template('user_profile_edit.html', user=user, influencer=influencer)

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
        return redirect(url_for('user_profile', username=session['username']))
    
    categories = Category.query.order_by(Category.category_name).all()
    if request.method == 'POST':
        name = request.form['name']
        description  = request.form['description']
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

@app.route('/view_campaigns', methods=['GET'])
@auth_required
def view_campaigns():
    user = User.query.filter_by(username=session['username']).first()
    profile_type = user.usertype
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

    campaigns = Campaign.query.filter_by(campaign_status='Created').all()
    return render_template('view_campaigns.html', user=user, campaigns=campaigns, profile_type=profile_type)

@app.route('/view_campaign', methods=['GET'])
@auth_required
def view_campaign():
    user = User.query.filter_by(username=session['username']).first()
    profile_type = user.usertype
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

    campaigns = Campaign.query.filter_by(campaign_status='Created').all()
    return render_template('view_campaign.html', user=user, campaigns=campaigns, profile_type=profile_type)

@app.route('/campaign/<int:campaign_id>/apply', methods=['POST'])
@auth_required
def apply_campaign(campaign_id):
    user = User.query.filter_by(username=session['username']).first()
    if user.usertype != 'influencer':
        flash('You are not an Influencer.', 'danger')
        return redirect(url_for('user_profile', username=session['username'])) 

    influencer = Influencer.query.filter_by(userid=user.userid).first()
    campaign = Campaign.query.get_or_404(campaign_id)

    if campaign.influencer_userid is not None:
        flash('This campaign already has an influencer.', 'danger')
        return redirect(url_for('view_campaigns'))


    campaign.influencer_userid = influencer.userid
    campaign.campaign_start = datetime.utcnow() 
    campaign.campaign_end = datetime.utcnow() + timedelta(days=campaign.campaign_duration)
    db.session.commit()

    flash('Successfully applied for the campaign!', 'success')
    return redirect(url_for('view_campaigns'))

@app.route('/campaign/<int:campaign_id>/edit', methods=['GET', 'POST'])
@auth_required
def edit_campaign(campaign_id):
    user = User.query.filter_by(username=session['username']).first()
    if not user or user.usertype != 'sponsor':
        flash('Access denied.', 'danger')
        return redirect(url_for('user_profile', username=session['username']))

    campaign = Campaign.query.get_or_404(campaign_id)
    if campaign.sponsor_userid != user.userid:
        flash('You do not have permission to edit this campaign.', 'danger')
        return redirect(url_for('view_campaigns'))

    categories = Category.query.order_by(Category.category_name).all()

    if request.method == 'POST':
        campaign.campaign_name = request.form['name']
        campaign.campaign_description = request.form['description']
        campaign.campaign_budget = request.form['budget']
        campaign.campaign_duration = request.form['duration']
        selected_categories = request.form.getlist('category[]')

        campaign.categories = []
        for category_id in selected_categories:
            category = Category.query.get(category_id)
            if category:
                campaign.categories.append(category)

        db.session.commit()
        flash('Campaign updated successfully', 'success')
        return redirect(url_for('user_profile', username=session['username']))

    return render_template('edit_campaign.html', campaign=campaign, categories=categories)

@app.route('/campaign/<int:campaign_id>/delete', methods=['POST'])
@auth_required
def delete_campaign(campaign_id):
    user = User.query.filter_by(username=session['username']).first()
    if not user or user.usertype != 'sponsor':
        flash('Access denied.', 'danger')
        return redirect(url_for('user_profile', username=session['username']))

    campaign = Campaign.query.get_or_404(campaign_id)
    if campaign.sponsor_userid != user.userid:
        flash('You do not have permission to delete this campaign.', 'danger')
        return redirect(url_for('view_campaigns'))

    db.session.delete(campaign)
    db.session.commit()
    flash('Campaign deleted successfully', 'success')
    return redirect(url_for('view_campaigns'))


@app.route('/request_influencer/<int:campaign_id>', methods=['POST'])
@auth_required
def request_influencer(campaign_id):
    current_user = get_current_user()
    campaign = Campaign.query.get_or_404(campaign_id)
    influencer_username = request.form['influencer_username']
    influencer = User.query.filter_by(username=influencer_username, usertype='influencer').first()

    if not influencer:
        flash('Influencer not found!', 'danger')
        return redirect(url_for('view_campaign'))

    if current_user.usertype != 'sponsor' or campaign.sponsor_userid != current_user.userid:
        abort(403)

    new_request = InfluencerRequest(
        campaign_id=campaign_id,
        influencer_id=influencer.userid,
        status='pending'
    )
    db.session.add(new_request)
    db.session.commit()
    flash('Influencer requested successfully!', 'success')
    return redirect(url_for('view_campaign'))

@app.route('/campaign/<int:campaign_id>/accept_influencer', methods=['POST'])
@auth_required
def accept_influencer(campaign_id):
    user = User.query.filter_by(username=session['username']).first()
    if user.usertype != 'sponsor':
        flash('You are not a Sponsor.', 'danger')
        return redirect(url_for('user_profile', username=session['username']))

    campaign = Campaign.query.get_or_404(campaign_id)
    if campaign.sponsor_userid != user.userid:
        flash('You do not have permission to accept applications for this campaign.', 'danger')
        return redirect(url_for('view_campaigns'))

    if campaign.influencer_userid is None:
        flash('No influencer has applied for this campaign.', 'danger')
        return redirect(url_for('view_campaigns'))

    flash('Influencer application accepted!', 'success')

    return redirect(url_for('view_campaigns'))

@app.route('/campaign/<int:campaign_id>/reject_influencer', methods=['POST'])
@auth_required
def reject_influencer(campaign_id):
    user = User.query.filter_by(username=session['username']).first()
    if user.usertype != 'sponsor':
        flash('You are not a Sponsor.', 'danger')
        return redirect(url_for('user_profile', username=session['username']))

    campaign = Campaign.query.get_or_404(campaign_id)
    if campaign.sponsor_userid != user.userid:
        flash('You do not have permission to reject applications for this campaign.', 'danger')
        return redirect(url_for('view_campaigns'))

    if campaign.influencer_userid is None:
        flash('No influencer has applied for this campaign.', 'danger')
        return redirect(url_for('view_campaigns'))

    flash('Influencer application rejected.', 'success')

    return redirect(url_for('view_campaigns'))

@app.route('/accept_campaign/<int:campaign_id>', methods=['POST'])
@auth_required
def accept_campaign(campaign_id):
    current_user = get_current_user()
    user = User.query.get(current_user.userid)
    campaign = Campaign.query.get(campaign_id)
    campaign_request = InfluencerRequest.query.filter_by(campaign_id=campaign_id, influencer_id=user.userid).first()

    if campaign and user and user.usertype == 'influencer' and campaign_request:
        campaign.influencer_userid = user.userid
        campaign.influencer_accepted = True
        campaign_request.status = 'accepted'
        
        db.session.commit()
        flash('Campaign accepted!', 'success')
    else:
        flash('Failed to accept campaign.', 'danger')

    return redirect(url_for('user_profile', username=current_user.username))

@app.route('/reject_campaign/<int:campaign_id>', methods=['POST'])
@auth_required
def reject_campaign(campaign_id):
    current_user = get_current_user()
    request_to_reject = InfluencerRequest.query.filter_by(campaign_id=campaign_id, influencer_id=current_user.id).first()

    if request_to_reject:
        request_to_reject.status = 'rejected'
        db.session.commit()
        flash('Campaign request rejected!', 'success')
    else:
        flash('Failed to reject campaign request.', 'danger')

    return redirect(url_for('user_profile', username=current_user.username))


@app.route('/report/<int:user_id>', methods=['POST'])
@auth_required
def report_user(user_id):
    reported_user = User.query.get_or_404(user_id)
    user = User.query.filter_by(username=session.get('username')).first()
    
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('user_profile', username=session['username']))
    
    reason = request.form.get('reason')
    if not reason:
        flash('Reason for reporting is required.', 'danger')
        return redirect(url_for('user_profile', username=reported_user.username))

    report = Report(
        reported_by=user.username,
        reported_user_id=reported_user.userid,
        reason=reason
    )
    db.session.add(report)
    db.session.commit()
    
    flash('Report submitted successfully.', 'success')
    return redirect(url_for('user_profile', username=reported_user.username))

@app.route('/admin/reports')
@auth_required
def view_reports():
    user = User.query.filter_by(username=session.get('username')).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('user_profile', username=session['username']))
    if user.usertype != 'admin':
        flash('You do not have permission to view this page.', 'danger')
        return redirect(url_for('user_profile', username=session['username']))
    reports = Report.query.all()
    return render_template('admin_reports.html', user=user, reports=reports)

@app.route('/admin/report/<int:report_id>/resolve', methods=['POST'])
@auth_required
def resolve_report(report_id):
    user = User.query.filter_by(username=session.get('username')).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('user_profile', username=session['username']))
    if user.usertype != 'admin':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('user_profile', username=session['username']))
    report = Report.query.get_or_404(report_id)
    report.status = 'Resolved'
    db.session.commit()
    flash('Report resolved successfully.', 'success')
    return redirect(url_for('view_reports'))

@app.route('/chart_data/registrations')
def chart_data_registrations():
    registrations = db.session.query(
        func.date(User.created_at),
        func.count(User.userid)
    ).group_by(func.date(User.created_at)).all()
    
    data = {
        'labels': [str(r[0]) for r in registrations],
        'values': [r[1] for r in registrations]
    }
    return jsonify(data)

@app.route('/chart_data/user_types')
def chart_data_user_types():
    user_types = db.session.query(
        User.usertype,
        func.count(User.userid)
    ).group_by(User.usertype).all()
    
    data = {
        'labels': [u[0] for u in user_types],
        'values': [u[1] for u in user_types]
    }
    return jsonify(data)

@app.route('/chart_data/campaigns')
def chart_data_campaigns():
    campaigns = db.session.query(
        func.date(Campaign.created_at),
        func.count(Campaign.campaignid)
    ).group_by(func.date(Campaign.created_at)).all()
    
    data = {
        'labels': [str(c[0]) for c in campaigns],
        'values': [c[1] for c in campaigns]
    }
    return jsonify(data)


@app.route('/chart_data/reports')
def chart_data_reports():
    reports = db.session.query(
        func.date(Report.timestamp),
        func.count(Report.id)
    ).group_by(func.date(Report.timestamp)).all()
    
    data = {
        'labels': [str(r[0]) for r in reports],
        'values': [r[1] for r in reports]
    }
    return jsonify(data)

@app.route('/chart_data/user_campaign_performance')
def chart_data_user_campaign_performance():
    current_user = get_current_user()
    user_id = current_user.userid
    campaign_performance = db.session.query(
        func.date(Campaign.created_at),
        func.count(Campaign.campaignid)
    ).filter_by(influencer_userid=user_id).group_by(func.date(Campaign.created_at)).all()
    
    data = {
        'labels': [str(cp[0]) for cp in campaign_performance],
        'values': [cp[1] for cp in campaign_performance]
    }
    return jsonify(data)


@app.route('/chart_data/revenue')
def revenue():
    campaign_revenue = db.session.query(
        func.strftime('%Y-%m', Campaign.start_date).label('month'),
        func.sum(Campaign.campaign_budget).label('total_budget')
    ).group_by('month').all()
    
    data = {
        'labels': [str(cr[0]) for cr in campaign_revenue],
        'values': [cr[1] for cr in campaign_revenue]
    }
    
    return jsonify(data)


@app.route('/charts')
def charts():
    current_user = get_current_user()
    user = current_user
    return render_template('charts.html', user=user)

@app.route('/privacy_policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

@app.route('/influencers')
@auth_required
def display_influencers():
    influencers = User.query.join(Influencer, User.userid == Influencer.userid).all()
    shuffle(influencers)
    return render_template('display_influencers.html', influencers=influencers)

@app.route('/sponsors')
@auth_required
def display_sponsors():
    sponsors = User.query.join(Sponsor, User.userid == Sponsor.userid).all()
    shuffle(sponsors)
    return render_template('display_sponsors.html', sponsors=sponsors)

@app.route('/search')
def search():
    query = request.args.get('query', '')
    if query:
        results = User.query.filter(User.username.contains(query) | User.name.contains(query)).all()
    else:
        results = []

    return render_template('search_results.html', query=query, results=results)
