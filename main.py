from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from forms import Item, Login, Register, ResetPassword, NewPassword
from bs4 import BeautifulSoup
from requests import get
from datetime import datetime
from flask_apscheduler import APScheduler
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_mail import Message, Mail
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.exc import IntegrityError
import os
import psycopg2


app = Flask(__name__)
Bootstrap(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI')
db = SQLAlchemy(app)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT')
scheduler = APScheduler()
login_manager = LoginManager()
login_manager.init_app(app)

mail_settings = {
    "MAIL_SERVER": 'smtp.gmail.com',
    "MAIL_PORT": 465,
    "MAIL_USE_TLS": False,
    "MAIL_USE_SSL": True,
    "MAIL_USERNAME": os.environ.get('MAIL_USERNAME'),
    "MAIL_PASSWORD": os.environ.get('MAIL_PASSWORD')
}
app.config.update(mail_settings)
mail = Mail(app)


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(255), unique=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    confirmed = db.Column(db.Integer)


class OnlinerTracker(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item = db.Column(db.String(255), nullable=False)
    current_price = db.Column(db.Float, nullable=False)
    acceptable_price = db.Column(db.Float, nullable=False)
    min_price = db.Column(db.Float, nullable=False)
    max_price = db.Column(db.Float, nullable=False)
    start_tracking_date = db.Column(db.String(50), nullable=False)
    link = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, )


db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)


@app.route('/')
def index():
    if current_user.is_authenticated:
        items = OnlinerTracker.query.filter_by(user_id=current_user.id).all()
        return render_template('index.html', items=items)
    else:
        return render_template('index.html')


@app.route('/new_item', methods=['GET', 'POST'])
@login_required
def new_item():
    form = Item()
    if form.validate_on_submit():
        item = form.name.data
        try:
            acceptable_price = float(form.acceptable_price.data)
        except ValueError:
            flash('Incorrect value.. Please try again', 'error')
            return render_template('item.html', form=form, title='New Item')
        link = form.link.data
        if get(link).status_code == 200:
            current_price = get_price(link)
            current_day = f'{datetime.now().day}.{datetime.now().month}.{datetime.now().year}'
            new_item = OnlinerTracker(
                item=item,
                current_price=current_price,
                acceptable_price=acceptable_price,
                min_price=current_price,
                max_price=current_price,
                start_tracking_date=current_day,
                link=link,
                user_id=current_user.id
            )
            db.session.add(new_item)
            db.session.commit()
            return redirect(url_for('index'))
        else:
            flash('Incorrect link.. Please try again', 'error')
            return render_template('item.html', form=form, title='New Item')
    return render_template('item.html', form=form, title='New Item')


@app.route('/edit_item', methods=['GET', 'POST'])
@login_required
def edit_item():
    item_id = request.args.get('item_id')
    item = OnlinerTracker.query.get(item_id)
    if item is None:
        item = OnlinerTracker.query.get(request.form['id'])
    if current_user.id == item.user_id:
        if request.method == 'POST':
            try:
                acceptable_price = float(request.form['acceptable_price'])
            except ValueError:
                form = Item(
                    id=item.id,
                    link=item.link,
                    name=item.item,
                    acceptable_price=item.acceptable_price
                )
                flash('Incorrect value.. Please try again', 'error')
                return render_template('item.html', form=form, title='Edit Item')
            item.item = request.form['name']
            item.acceptable_price = acceptable_price
            db.session.commit()
            return redirect(url_for('index'))
        else:
            form = Item(
                id=item.id,
                link=item.link,
                name=item.item,
                acceptable_price=item.acceptable_price
            )
            return render_template('item.html', form=form, title='Edit Item')
        return redirect(url_for('index'))
    else:
        return redirect(url_for('index'))


@app.route('/delete_item', methods=['GET'])
@login_required
def delete_item():
    item_id = request.args.get('item_id')
    item = OnlinerTracker.query.get(item_id)
    if current_user.id == item.user_id:
        db.session.delete(item)
        db.session.commit()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = Register()
    if form.validate_on_submit():
        if form.password.data == form.confirm_password.data:
            new_user = Users(
                login=form.login.data,
                email=form.email.data,
                password=generate_password_hash(form.password.data, salt_length=32)
            )
            try:
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                token = generate_confirm_token(form.email.data)
                confirm_url = 'http://catalog-onliner.herokuapp.com' + url_for('confirm', token=token)
                html = render_template('confirm.html', confirm_url=confirm_url)
                msg = Message(
                    subject='Email Confirm',
                    sender=app.config.get('MAIL_USERNAME'),
                    recipients=form.email.data.split(),
                    html=html
                )
                mail.send(msg)
            except IntegrityError:
                flash('Login or email already exists', 'error')
                return render_template('register.html', form=form)
            flash('Thanks for sign up. Please confirm email address. Activation link was sent on your email.',
                  'success')
            return redirect(url_for('index'))
        else:
            flash("Passwords doesn't match.. Try again", 'error')
            return render_template('register.html', form=form)
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Login()
    if form.validate_on_submit():
        name = form.name.data
        if '@' in name:
            user = Users.query.filter_by(email=name).first()
        else:
            user = Users.query.filter_by(login=name).first()
        if user is None:
            flash('Incorrect email/login or password', 'error')
            return render_template('login.html', form=form)
        else:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('index'))
            else:
                flash('Incorrect email/login or password', 'error')
                return render_template('login.html', form=form)
    return render_template('login.html', form=form)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    form = ResetPassword()
    if request.method == 'POST':
        name = form.name.data
        if '@' in name:
            user = Users.query.filter_by(email=name).first()
        else:
            user = Users.query.filter_by(login=name).first()
        if user:
            token = generate_confirm_token(user.email)
            confirm_url = 'http://catalog-onliner.herokuapp.com' + url_for('forgot', token=token)
            html = render_template('reset.html', confirm_url=confirm_url)
            msg = Message(
                subject='Reset Password',
                sender=app.config.get('MAIL_USERNAME'),
                recipients=[user.email],
                html=html
            )
            mail.send(msg)
            flash('Reset password link was sent on your email.', 'success')
            return redirect(url_for('login'))
        else:
            flash('No user with this email', 'error')
            return render_template('reset_password.html', form=form)
    return render_template('reset_password.html', form=form)


@app.route('/forgot/<token>', methods=['GET', 'POST'])
def forgot(token):
    form = NewPassword()
    email = confirm_token(token)
    user = Users.query.filter_by(email=email).first()
    if user:
        if request.method == 'POST':
            if form.password.data == form.confirm_password.data:
                user.password = generate_password_hash(form.password.data, salt_length=24)
                db.session.commit()
                return redirect(url_for('login'))
            else:
                return render_template('new_password.html', form=form, token=token)
        return render_template('new_password.html', form=form, token=token)
    else:
        return redirect(url_for('index'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


def get_price(link):
    response = get(link)
    soup = BeautifulSoup(response.text, 'lxml')
    price = soup.find('a', class_='offers-description__link offers-description__link_nodecor')
    if price is None:
        return 0
    else:
        price = price.text.strip().split(',')
        return float(f'{price[0]}.{price[1][0:2]}')


def update_prices():
    with app.app_context():
        all_items = OnlinerTracker.query.all()
        for item in all_items:
            new_price = get_price(item.link)
            item.current_price = new_price
            if new_price > item.max_price:
                item.max_price = new_price
            elif new_price < item.min_price:
                item.min_price = new_price
            if new_price < item.acceptable_price and new_price != 0:
                user = Users.query.get(item.user_id)
                message = f'Hello, {user.login}\nYour tracking item {item.item} price now is {new_price}!\nLink: {item.link}'
                msg = Message(body=message, subject='OnlinerTracker', sender=app.config.get('MAIL_USERNAME'),
                              recipients=[user.email])
                mail.send(msg)
        db.session.commit()


def generate_confirm_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])


def confirm_token(token):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'])
    except:
        return False
    return email


@app.route('/confirm/<token>')
def confirm(token):
    email = confirm_token(token)
    user = Users.query.filter_by(email=email).first()
    if user.confirmed:
        flash('Email already confirmed', 'success')
        return redirect(url_for('index'))
    else:
        user.confirmed = 1
        db.session.commit()
        flash("Email confirmed", 'success')
    return redirect(url_for('index'))


if __name__ == '__main__':
    # scheduler.add_job(id='Update_price', func=update_prices, trigger='interval', seconds=86400)
    # scheduler.start()
    app.run()
