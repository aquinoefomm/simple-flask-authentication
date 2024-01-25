from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy()
db.init_app(app)


# FLASK LOGIN MANAGER
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
user_logged_in = False


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# CREATE TABLE IN DB
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

 
with app.app_context():
    db.create_all()


@app.route('/')
def home():
    global user_logged_in
    return render_template("index.html", logged_in=user_logged_in)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        hashed_password = generate_password_hash(request.form['password'], method='pbkdf2:sha256', salt_length=8)
        new_user = User(
            email=request.form['email'],
            password=hashed_password,
            name=request.form['name'],
        )
        exists = db.session.query(User).filter_by(email=new_user.email).scalar()
        if exists:
            flash("User already exists...")
            return redirect(url_for('login'))
        else:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    else:
        return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    global user_logged_in
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user:
            if check_password_hash(user.password, request.form['password']):
                login_user(user)
                user_logged_in = True
                flash("Login successful!")
                return redirect(url_for('secrets', name=user.name, logged_in=user_logged_in))
            else:
                flash("Incorrect password😓. Please try again!")
                return render_template('login.html')
        else:
            flash("User not found 😓. Please try again!")
            return render_template('login.html')
    else:
        return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", user=current_user, logged_in=user_logged_in)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    global user_logged_in
    if user_logged_in:
        logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory('static', path="files/cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)
