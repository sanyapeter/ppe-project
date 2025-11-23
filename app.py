from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt


app = Flask(__name__)  # creating the web app

# CONFIG MUST COME BEFORE db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/sanya/ppe_app/database.db'# Stores all the data in database.db
app.config['SECRET_KEY'] = "put_the_secret_key_here"
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)  # creating a database for users

login_manager = LoginManager()
login_manager.init_app(app) 
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) #return user object by id

class User(db.Model, UserMixin):  # creating a table for users
    id = db.Column(db.Integer, primary_key=True)  # column for id
    username = db.Column(db.String(20), nullable=False,unique=True)  # column for username max 20, shouldnt be null, should be unique
    password = db.Column(db.String(80), nullable=False, unique=True)  # column for password max 80 (after hasing)

class RegisterForm(FlaskForm): #secureforum
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"}) #textbox for username
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"}) # textbox for password
    submit = SubmitField('Register') #create sregister button

    # Validates if a user exits or not
    def validate_username(self, username):
        #checks existing usernames
        existing_user_username = User.query.filter_by(username=username.data).first()
        
        if existing_user_username: # gives a validation eror
            raise ValidationError(
                'That username already exists. Please choose a different one.') 

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')


@app.route('/') #adds Url to the function in this case / = homepage

# HOME PAGE
def home():
    return render_template('home.html') # running content inside home.html

# LOGIN PAGE
@app.route('/login',methods=['GET', 'POST']) #adds Url to the function for login
def login():
    form=LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first() #checling for userid
        if user: 
            if bcrypt.check_password_hash(user.password, form.password.data): # checking if password matches
                login_user(user) #lets user in
                return redirect(url_for('dashboard')) #sends to dashboard
    return render_template('login.html',form=form) #runnning content inside login.html

# DASHBOARD
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

#LOGOUT
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# REGISTER PAGE
@app.route('/register',methods=['GET', 'POST'])
def register():
    form=RegisterForm()
    if form.validate_on_submit(): # validatiin when you submit
        hashed_password = bcrypt.generate_password_hash(form.password.data) #creating a hashed passwprd
        new_user = User(username=form.username.data, password=hashed_password) # creates new user using database
        db.session.add(new_user) # adds new user to the database
        db.session.commit() # savews the new user
        return redirect(url_for('login')) #once registration is successful redirects to login page

    return render_template('register.html', form=form)
    return render_template('register.html',form=form) # running content inside register


if __name__ == '__main__':
    app.run(debug=True) #to catch errors