from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from email import message
import smtplib, ssl
import os
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField,TextAreaField, SubmitField
from wtforms.validators import InputRequired, Email,Length
from flask.helpers import flash
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import LoginManager,UserMixin,login_user,login_required,logout_user,current_user
from hashlib import md5

app = Flask(__name__)
app.config['DEBUG'] = True
app.secret_key = "covid19 application"
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = 'covid19 application'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' 

class LoginForm(FlaskForm):
    name = StringField('name',validators=[InputRequired(),Length(min=2,max=20)])
    password = PasswordField('password',validators=[InputRequired(),Length(min=8,max=15)])

class RegisterForm(FlaskForm):
    email = StringField('email',validators=[InputRequired(),Email(message='Invalid email'),Length(max=50)])
    gender = StringField('gender',validators=[InputRequired()])
    name = StringField('name',validators=[InputRequired(),Length(min=2,max=20)])
    phone = StringField('phone',validators=[InputRequired(),Length(max=15)])
    password = PasswordField('password',validators=[InputRequired(),Length(min=8,max=15)])

class Contacts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=False, nullable=False)
    phone = db.Column(db.String(13),unique=True,nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    message = db.Column(db.String(80),  nullable=False)

class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=False, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(15), unique=False, nullable=False)
    phone = db.Column(db.Integer,unique=False,nullable=False)
    gender = db.Column(db.String(80),nullable=False)

    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(digest, size)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
              
@app.route("/")
@login_required
def index():
    return render_template('index.html')


@app.route("/login",methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(name=form.name.data).first()
        if user is not None:            
            if check_password_hash(user.password,form.password.data):
                login_user(user)
                return redirect(url_for('index'))
        return '<h1>Invalid username or password</h1>'
    return render_template('login.html',form=form)


@app.route('/login/phase2',methods=['GET','POST'])
def loginPhase2():
    form = LoginForm()
    if request.method == 'POST' :
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(name=form.name.data).first()
        if user is not None:            
            if check_password_hash(user.password,form.password.data):
                login_user(user)
                return redirect(url_for('index'))
        return '<h1>Invalid username or password</h1>'
    return render_template('login.html',form=form)

@app.route("/signup",methods=['GET','POST'])
def signup():
    # print("\n\n\nSIGNUP\n\n\n")
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password  = generate_password_hash(form.password.data,method='sha256')
        new_user = User(name=form.name.data , email= form.email.data,password=hashed_password,phone=form.phone.data,gender=form.gender.data)
        db.session.add(new_user)
        db.session.commit()
        # print("\n\nSIGNUP DB INSERTED\n\n")
        return redirect(url_for('login'))
    return render_template('signup.html',form=form)

@app.route('/signup/phase2', methods=['GET', 'POST'])
def signupPhase2():
    form = RegisterForm()
    if request.method == 'POST':
        name = request.form.get('name')
        gender = request.form.get('gender')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')
        hashed_password  = generate_password_hash(password,method='sha256')
        new_user = User(name=name , email= email , phone=phone , password=hashed_password,gender=gender)
        db.session.add(new_user)
        db.session.commit()
        # print("\n\nSIGNUP DB INSERTED\n\n")
        return redirect(url_for('login'))
    return render_template('signup.html',form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))
    
@app.route("/about",methods=['GET', 'POST'])
@login_required
def about():
    return render_template('about.html')

@app.route("/action",methods=['GET', 'POST'])
@login_required
def action():
    return render_template('action.html')

@app.route("/quotes",methods=['GET', 'POST'])
@login_required
def quotes():
    return render_template('quotes.html')

@app.route("/news",methods=['GET', 'POST'])
@login_required
def news():
    return render_template('news.html')

@app.route("/session",methods=['GET','POST'])
def session():
    if request.method=='POST' :
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        message = request.form.get('message')
        entry = Contacts(name=name , phone=phone , message=message,email=email)
        db.session.add(entry)
        db.session.commit()
        port = 465  # For SSL
        smtp_server = "smtp.gmail.com"
        receiver_email = email
        sender_email = "bewithsayan2819@gmail.com"  # Enter your address
        password = "sayanmondalronaldo"
        message = message
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message)
    return render_template('index.html')

@app.route("/contact",methods=['GET', 'POST'])
@login_required
def contact():
    return render_template('contact.html')


@app.route('/user/<name>')
@login_required
def user(name):
    user = User.query.filter_by(name=name).first_or_404()
    return render_template('user.html', user=user)


if __name__ == '__main__':
    app.run(debug=True)
