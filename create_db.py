from app import app, db
from models import Category, User
from werkzeug.security import generate_password_hash

def create_category_table():
    with app.app_context():
        db.create_all()

        if Category.query.count() == 0:
            categories = [
                Category(category_name='Fashion'),
                Category(category_name='Technology'),
                Category(category_name='Food'),
                Category(category_name='Fitness'),
                Category(category_name='Beauty'),
                Category(category_name='Travel'),
                Category(category_name='Gaming'),
                Category(category_name='Music'),
                Category(category_name='Health'),
                Category(category_name='Finance'),
                Category(category_name='Education'),
                Category(category_name='Pets'),
                Category(category_name='Books'),
                Category(category_name='Sports'),
                Category(category_name='Home Decor'),
                Category(category_name='Automotive'),
                Category(category_name='Photography'),
                Category(category_name='Parenting'),
                Category(category_name='Social Media'),
                Category(category_name='Marketing'),
                Category(category_name='Entertainment'),
                Category(category_name='Lifestyle'),
                Category(category_name='Cooking'),
                Category(category_name='DIY & Crafts'),
                Category(category_name='Tech Gadgets'),
                Category(category_name='Fashion Accessories'),
                Category(category_name='Environmental Sustainability'),
                Category(category_name='Business & Entrepreneurship'),
                Category(category_name='Science & Technology'),
                Category(category_name='Travel & Adventure'),
                Category(category_name='Interior Design'),
                Category(category_name='Outdoor & Camping'),
                Category(category_name='Weddings & Events'),
                Category(category_name='Fitness & Wellness'),
                Category(category_name='Spirituality & Mindfulness'),
                Category(category_name='History & Culture'),
                Category(category_name='Fashion & Style'),
                Category(category_name='Parenting & Family'),
                Category(category_name='Music & Dance'),
                Category(category_name='Film & TV'),
                Category(category_name='Art & Design'),
                Category(category_name='Food & Drink'),
                Category(category_name='Home Improvement'),
                Category(category_name='Gardening & Plants'),
                Category(category_name='Pets & Animals'),
            ]
            db.session.bulk_save_objects(categories)
            db.session.commit()

def create_admin():
    with app.app_context():
        admin = User.query.filter_by(usertype='admin').first()
        if not admin:
            username = 'admin'
            password = 'adminpassword'
            passhash = generate_password_hash(password)
            profile_pic = 'static/logo.jpeg'
            new_admin = User(
                username=username,
                passhash=passhash,
                usertype='admin',
                name='Admin',
                email='admin@collabsphere.com',
                profile_pic=profile_pic
            )
            db.session.add(new_admin)
            db.session.commit()
            print("Admin user created successfully")
        else:
            print("Admin user already exists")


if __name__ == '__main__':
    create_category_table()
    create_admin()
