from flask import Flask, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import secrets
import os
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask import current_app
from email_validator import validate_email, EmailNotValidError

load_dotenv()

app = Flask(__name__)

# Configure db
DATABASE_URL = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL # połączenie z db
app.config['SECRET_KEY'] = secrets.token_hex(16) # klucz do szyfrowania sesji
app.config.from_pyfile('config.py') # wczytanie konfiguracji z pliku config.py dotyczącego maila
db = SQLAlchemy(app) #obiekt bd
login_manager = LoginManager(app) # obiekt do zarządzania logowaniem sesją użytkownika i ciasteczkami
mail = Mail(app)
login_manager.login_view = '/' # przekierowanie na stronę logowania


@login_manager.user_loader # funkcja do logowania użytkownika
def load_user(user_id):
    return User.query.get(int(user_id)) # pobieramy użytkownika o podanym id

class User(db.Model, UserMixin):  # Tworzymy użytkownika
    id = db.Column(db.Integer, primary_key=True) 
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    tasks = db.relationship('TODO', backref='user', lazy=True)  # relacja jeden do wielu (uselist=True domyślnie), jeden użytkownik może mieć wiele zadań, backref tworzy kolumnę w drugiej tabeli
    verified = db.Column(db.Boolean, default=False) # czy zweryfikowany
    

class TODO(db.Model): # model tabeli (dziedziczy z klasy model)
    id = db.Column(db.Integer, primary_key=True) # Unikalny indentyfikator, klucz głowny
    content = db.Column(db.String(200),nullable=False) # tytuł, nie może być pusty, postać string do 200 znaków
    date_created = db.Column(db.DateTime, default=datetime.utcnow) # data utworzenia, domyślnie aktualna data
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    complete = db.Column(db.Boolean) # czy zrobione # klucz obcy, odwołuje się do id użytkownika, nie może być pusty

    def __repr__(self):
        return '<Task %r>' % self.id # wyświetla id zadania za każdym razem jak jakieś stworzymy
    

    
    
with app.app_context():
    # Teraz możesz wywoływać operacje bazodanowe
    db.create_all()


@app.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        logout_user()
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        user = User.query.filter_by(username=login).first() # pobieramy użytkownika o podanym username
        if user and user.password == password and user.verified == True: #sprawdzamy czy haslo jest poprawne
            login_user(user)
            return render_template('index.html', tasks=current_user.tasks)
        elif user and user.password == password and user.verified == False:
            return render_template('verify.html', message='Account has not been verified yet.')
        else:
            return render_template('home.html', message='Wrong username or password')
    else:
        return render_template('home.html')
    

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        email = request.form['email']
        exist = User.query.filter_by(email=email).first() # sprawdzamy czy użytkownik o podanym emailu już istnieje
        exist_login = User.query.filter_by(username=login).first() # sprawdzamy czy użytkownik o podanym loginie już istnieje
        try:
            valid = validate_email(email) # sprawdzamy czy email jest poprawny
            email = valid.email
        except EmailNotValidError as e:
            return render_template('register.html', message='Email is not valid')
        if exist == None and exist_login == None and len(password) >= 8 and len(login) >= 3:
            new_user = User(username=login, password=password, email=email)
            try:
                db.session.add(new_user)
                db.session.commit()
                return render_template('verify.html')
            except:
                return 'There was an issue adding new user'
        elif exist == None and exist_login == None:
            return render_template('register.html', message='Password must be at least 8 characters long and login at least 3 characters long')
        else:
            return render_template('register.html', message='User with this email or login already exists')
    else:
        return render_template('register.html')
    

    
@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user == None:
            return render_template('verify.html', message='User with this email does not exist')
        elif user.verified == True:
            return render_template('verify.html', message='Account has been already verified')
        else:
            secret_key = current_app.config['SECRET_KEY'] # pobieramy klucz do szyfrowania
            expiration_time = 1800 # czas ważności linku w sekundach
            serializer = URLSafeTimedSerializer(secret_key, expiration_time) # tworzymy obiekt do szyfrowania
            token = serializer.dumps(user.id, salt='verification-salt') # szyfrujemy po id użytkownika
            link = url_for('confirm_email', token=token, _external=True) # tworzymy link do potwierdzenia
            subject = 'Potwierdzenie konta'
            body = f'Kliknij link, aby potwierdzić konto: {link}'
            message = Message(subject, recipients=[email], body=body)
            try:
                mail.send(message)
                return render_template('verify.html', message='Link has been sent to your email')
            except:
                return 'There was an issue sending email'



@app.route('/confirm_email/<token>')
def confirm_email(token):
    # Weryfikacja tokena
    user_id = verify_verification_token(token)
    user = User.query.get(user_id)

    if user:
        user.verified = True
        db.session.commit()
        return render_template('home.html', message='Account has been verified. You can log in now.')
    else:
        return render_template('verify.html', message='The confirmation link is invalid or has expired.')
    


def verify_verification_token(token):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        user_id = serializer.loads(
            token,
            salt='verification-salt',
            max_age=1800
        )
    except:
        return False
    return user_id



@app.route('/tasks', methods=['POST','GET']) # to wyświetli się na stronie głównej, route odpowiada za ścieżkę, domyślna / jest główna
def index():
    if not current_user.is_authenticated:
        return redirect('/')
    user = current_user
    if request.method == 'POST':
        task_content = request.form['content'] # pobieramy dane z formularza
        new_task = TODO(content=task_content, user = user,complete=False) # tworzymy nowy obiekt tabeli
        try:
            db.session.add(new_task) # dodajemy do sesji
            db.session.commit() # zapisujemy zmiany
            return redirect('/tasks') # przekierowanie na stronę główną
        except:
            return 'There was an issue adding your task'
    else:
        tasks = TODO.query.filter_by(user_id=user.id, complete=False).order_by(TODO.date_created).all() # pobieramy wszystkie zadania z bazy danych
        return render_template('index.html', tasks=tasks) # przekazujemy je do szablonu
    
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect('/')

@app.route('/delete/<int:id>') # <int:id> oznacza, że id jest liczbą całkowitą
def delete(id):
    task_to_delete = TODO.query.get_or_404(id) # pobieramy zadanie o podanym id
    user = current_user

    try:
        db.session.delete(task_to_delete) # usuwamy
        db.session.commit() # zapisujemy zmiany
        tasks = TODO.query.filter_by(user_id=user.id, complete=False).order_by(TODO.date_created).all()
        return render_template('index.html', tasks=tasks) # przekierowanie na stronę główną
    except:
        return 'There was a problem deleting that task'
    
@app.route('/update/<int:id>', methods=['GET','POST']) # methods są potrzebne, bo domyślnie jest GET, a my chcemy wpisywać za pomocą edit
def update(id):
    task_to_update = TODO.query.get_or_404(id) # pobieramy zadanie o podanym id
    if request.method == 'POST':
        task_to_update.content = request.form['content'] # przypisujemy nową treść
        try:
            db.session.commit() # zapisujemy zmiany
            return redirect('/tasks') # przekierowanie na stronę główną
        except:
            return 'There was an issue updating your task'
    else:
        return render_template('update.html', task=task_to_update) # przekazujemy je do szablonu
    
@app.route('/done/<int:id>')
def coplete(id):
    task_to_complete = TODO.query.get_or_404(id)
    task_to_complete.complete = True
    user = current_user
    try:
        db.session.commit()
        tasks = TODO.query.filter_by(user_id=user.id, complete=False).order_by(TODO.date_created).all()
        return render_template('index.html', tasks=tasks)
    except:
        return 'There was an issue completing your task'
    
        
