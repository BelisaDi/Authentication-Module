from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_required, current_user, login_user, logout_user, login_required, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from flask_session_captcha import FlaskSessionCaptcha
from flask_sessionstore import Session
from random import randint
from time import sleep
from datetime import datetime, timedelta

db = SQLAlchemy()

app = Flask(__name__)
app.config["DEBUG"] = True

app.config["SECRET_KEY"] = str(uuid.uuid4())
app.config['CAPTCHA_ENABLE'] = True
app.config['CAPTCHA_LENGTH'] = 5
app.config['CAPTCHA_WIDTH'] = 160
app.config['CAPTCHA_HEIGHT'] = 60
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['CAPTCHA_SESSION_KEY'] = 'captcha_image'

Session(app)
captcha = FlaskSessionCaptcha(app)
db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    # primary keys are required by SQLAlchemy
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    created_at = db.Column(db.DateTime, default=datetime.now())
    last_failed_login = db.Column(db.DateTime, default = datetime.now())
    num_failed_login = db.Column(db.Integer, default = 0)


db.create_all(app=app)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/profile')
@login_required
def profile():
    num_fl = current_user.num_failed_login
    if current_user.last_failed_login != current_user.created_at:
        dat = 'on ' + str(current_user.last_failed_login)
    else:
        dat = 'never'
    current_user.num_failed_login = 0
    db.session.commit()

    return render_template('profile.html', name=current_user.name, date = dat, num = num_fl)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if captcha.validate():
            sleep(randint(1, 3))
            email = request.form.get('email')
            password = request.form.get('password')
            remember = True if request.form.get('remember') else False

            user = User.query.filter_by(email=email).first()

            if not user:
                flash('Please check your login details and try again.')
                return redirect(url_for('login'))

            if user.num_failed_login != 0 and (user.num_failed_login % 3 == 0):
                if (datetime.now() - user.last_failed_login).seconds <= 10*60:
                    flash('The account has been blocked for 10 minutes, try again later.')
                    return redirect(url_for('login'))
                else:
                    if not check_password_hash(user.password, password):
                        user.last_failed_login = datetime.now()
                        user.num_failed_login += 1
                        db.session.commit()
                        flash('Please check your login details and try again.')
                        return redirect(url_for('login'))

                    login_user(user, remember=remember)
                    return redirect(url_for('profile'))

            if not check_password_hash(user.password, password):
                user.last_failed_login = datetime.now()
                user.num_failed_login += 1
                db.session.commit()
                flash('Please check your login details and try again.')
                return redirect(url_for('login'))


            login_user(user, remember=remember)
            return redirect(url_for('profile'))
        else:
            flash('Incorrept captcha, try again.')
            return redirect(url_for('login'))
    else:
        return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user:
            flash('Email address already exists')
            return redirect(url_for('signup'))

        new_user = User(email=email, name=name, password=generate_password_hash(
            password, method='sha256'))

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))
    else:
        return render_template('signup.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

app.run(host = "0.0.0.0", port = 5000)
