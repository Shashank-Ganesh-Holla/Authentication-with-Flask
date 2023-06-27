from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory, abort, \
    get_flashed_messages
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import os
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, EmailField, PasswordField
from wtforms.validators import InputRequired

app = Flask(__name__)
db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'users.db')

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


# Line below only required once, when creating DB.
# db.create_all()


# class UserFormSignup(FlaskForm):
#     name = StringField(validators=[InputRequired()], render_kw={"placeholder": "Name"})
#     email = EmailField(validators=[InputRequired()], render_kw={"placeholder": "Email"})
#     password = PasswordField(validators=[InputRequired()], render_kw={"placeholder": "Password"})


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    bol = False
    if current_user.is_authenticated:
        bol = True
    return render_template("index.html", logged_in=bol)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        email = request.form.get('email')
        search_user = db.session.query(User).filter_by(email=email).all()
        print(search_user)
        if search_user:
            flash("You've already signed up with that email, log in instead!")
            return render_template('login.html')
        name = request.form.get('name')
        password_retrieve = request.form.get('password')
        password = generate_password_hash(password=password_retrieve, method='pbkdf2:sha256', salt_length=8)

        try:
            new_user = User(email=email, name=name, password=password)
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            return redirect(url_for('secrets', name=new_user.name))
        except IntegrityError as err:
            print(repr(err))
            return redirect(url_for('home'))
    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        pword = request.form.get('password')

        user = db.session.query(User).filter_by(email=email).first()
        if user:
            if check_password_hash(pwhash=user.password, password=pword):
                login_user(user)
                return redirect(url_for('secrets'))
            else:
                flash('Invalid Password')
                return redirect(url_for("login"))
        else:
            flash('Invalid User')
            return redirect(url_for('login'))

    return render_template("login.html")


@login_required
@app.route('/secrets')
def secrets():
    if current_user.is_authenticated:
        name = current_user.name
        bol = True
        return render_template("secrets.html", name=name, logged_in=bol)
    else:
        abort(401)  # Unauthorized


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@login_required
@app.route('/download')
def download():
    return send_from_directory(directory='static', path='files/cheat_sheet.pdf')


if __name__ == "__main__":
    app.run(debug=True)
