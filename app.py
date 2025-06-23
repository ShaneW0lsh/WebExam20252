from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, date
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import markdown2
import bleach
from forms import LoginForm, EventForm, RegistrationForm
from functools import wraps
from flask_wtf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
# POSTGRES_USER = os.environ.get('POSTGRES_USER', 'postgres')
# POSTGRES_PASSWORD = os.environ.get('POSTGRES_PASSWORD', 'postgres')
# POSTGRES_DB = os.environ.get('POSTGRES_DB', 'volunteers_db')
# POSTGRES_HOST = os.environ.get('PGHOST', 'localhost')
# POSTGRES_PORT = os.environ.get('PGPORT', '5432')

# app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'

csrf = CSRFProtect(app)

@app.template_filter('markdown')
def markdown_filter(text):
    return markdown2.markdown(text or "")

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)

# Models
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)
    users = db.relationship('User', backref='role', lazy=True)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(512), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    first_name = db.Column(db.String(80), nullable=False)
    middle_name = db.Column(db.String(80))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    organized_events = db.relationship('Event', backref='organizer', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date = db.Column(db.Date, nullable=False)
    location = db.Column(db.String(200), nullable=False)
    volunteers_needed = db.Column(db.Integer, nullable=False)
    image_filename = db.Column(db.String(100), nullable=False)
    organizer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    registrations = db.relationship('Registration', backref='event', lazy=True, cascade='all, delete-orphan')

class Registration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id', ondelete='CASCADE'), nullable=False)
    volunteer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    contact_info = db.Column(db.String(200), nullable=False)
    registration_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False, default='pending')
    volunteer = db.relationship('User', backref='registrations')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role.name != 'administrator':
            flash('У вас недостаточно прав для выполнения данного действия', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def moderator_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role.name not in ['administrator', 'moderator']:
            flash('У вас недостаточно прав для выполнения данного действия', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    events = Event.query.filter(Event.date >= date.today()).order_by(Event.date.desc()).paginate(page=page, per_page=10)
    return render_template('index.html', events=events)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Невозможно аутентифицироваться с указанными логином и паролем', 'danger')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or not next_page.startswith('/'):
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/event/create', methods=['GET', 'POST'])
@admin_required
def create_event():
    form = EventForm()
    if form.validate_on_submit():
        try:
            file = form.image.data
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            event = Event(
                title=form.title.data,
                description=bleach.clean(form.description.data),
                date=form.date.data,
                location=form.location.data,
                volunteers_needed=form.volunteers_needed.data,
                image_filename=filename,
                organizer_id=current_user.id
            )
            db.session.add(event)
            db.session.commit()
            flash('Мероприятие успешно создано', 'success')
            return redirect(url_for('view_event', event_id=event.id))
        except Exception as e:
            db.session.rollback()
            flash('При сохранении данных возникла ошибка. Проверьте корректность введённых данных.', 'danger')
    return render_template('event_form.html', form=form)

@app.route('/event/<int:event_id>')
def view_event(event_id):
    event = Event.query.get_or_404(event_id)
    registration_form = RegistrationForm()
    event.description = markdown2.markdown(event.description)
    return render_template('event_view.html', event=event, registration_form=registration_form)

@app.route('/event/<int:event_id>/edit', methods=['GET', 'POST'])
@moderator_required
def edit_event(event_id):
    event = Event.query.get_or_404(event_id)
    form = EventForm(obj=event)
    form.image.validators = []  # Remove image validation for edit form
    
    if form.validate_on_submit():
        try:
            event.title = form.title.data
            event.description = bleach.clean(form.description.data)
            event.date = form.date.data
            event.location = form.location.data
            event.volunteers_needed = form.volunteers_needed.data
            
            db.session.commit()
            flash('Мероприятие успешно обновлено', 'success')
            return redirect(url_for('view_event', event_id=event.id))
        except:
            db.session.rollback()
            flash('При сохранении данных возникла ошибка. Проверьте корректность введённых данных.', 'danger')
    
    return render_template('event_form.html', form=form, event=event)

@app.route('/event/<int:event_id>/delete', methods=['POST'])
@admin_required
def delete_event(event_id):
    event = Event.query.get_or_404(event_id)
    try:
        if event.image_filename:
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], event.image_filename)
            if os.path.exists(image_path):
                os.remove(image_path)
        
        db.session.delete(event)
        db.session.commit()
        flash('Мероприятие успешно удалено', 'success')
    except:
        db.session.rollback()
        flash('Произошла ошибка при удалении мероприятия', 'danger')
    return redirect(url_for('index'))

@app.route('/event/<int:event_id>/register', methods=['POST'])
@login_required
def register_for_event(event_id):
    if current_user.role.name != 'user':
        flash('Только пользователи могут регистрироваться на мероприятия', 'danger')
        return redirect(url_for('view_event', event_id=event_id))
    
    event = Event.query.get_or_404(event_id)
    if event.date < date.today():
        flash('Невозможно зарегистрироваться на прошедшее мероприятие', 'danger')
        return redirect(url_for('view_event', event_id=event_id))
    
    existing_registration = Registration.query.filter_by(
        event_id=event_id,
        volunteer_id=current_user.id
    ).first()
    
    if existing_registration:
        flash('Вы уже зарегистрированы на это мероприятие', 'warning')
        return redirect(url_for('view_event', event_id=event_id))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            registration = Registration(
                event_id=event_id,
                volunteer_id=current_user.id,
                contact_info=form.contact_info.data
            )
            db.session.add(registration)
            db.session.commit()
            flash('Ваша заявка успешно отправлена', 'success')
        except:
            db.session.rollback()
            flash('Произошла ошибка при регистрации', 'danger')
    return redirect(url_for('view_event', event_id=event_id))

@app.route('/event/<int:event_id>/registration/<int:registration_id>/update', methods=['POST'])
@moderator_required
def update_registration_status(event_id, registration_id):
    registration = Registration.query.get_or_404(registration_id)
    if registration.event_id != event_id:
        abort(404)
    
    new_status = request.form.get('status')
    if new_status not in ['accepted', 'rejected']:
        abort(400)
    
    try:
        registration.status = new_status
        if new_status == 'accepted':
            # Check if we need to reject other pending registrations
            accepted_count = Registration.query.filter_by(
                event_id=event_id,
                status='accepted'
            ).count()
            
            if accepted_count >= registration.event.volunteers_needed:
                # Reject all remaining pending registrations
                pending_registrations = Registration.query.filter_by(
                    event_id=event_id,
                    status='pending'
                ).all()
                for reg in pending_registrations:
                    reg.status = 'rejected'
        
        db.session.commit()
        flash('Статус регистрации обновлен', 'success')
    except:
        db.session.rollback()
        flash('Произошла ошибка при обновлении статуса', 'danger')
    
    return redirect(url_for('view_event', event_id=event_id))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create roles if they don't exist
        roles = [
            ('administrator', 'Администратор системы'),
            ('moderator', 'Модератор мероприятий'),
            ('user', 'Обычный пользователь')
        ]
        
        for role_name, role_desc in roles:
            if not Role.query.filter_by(name=role_name).first():
                role = Role(name=role_name, description=role_desc)
                db.session.add(role)
        
        # Create admin user if it doesn't exist
        admin_role = Role.query.filter_by(name='administrator').first()
        if admin_role and not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                last_name='Администратор',
                first_name='Системы',
                role_id=admin_role.id
            )
            admin.set_password('admin')
            db.session.add(admin)
        
        moderator_role = Role.query.filter_by(name='moderator').first()
        if moderator_role and not User.query.filter_by(username='moderator').first():
            moderator = User(
                username='moderator',
                last_name='Модератор',
                first_name='Системы',
                role_id=moderator_role.id
            )
            moderator.set_password('moderator')
            db.session.add(moderator)

        user_role = Role.query.filter_by(name='user').first()
        for i in range(1, 7):
            username = f'user{i}'
            if user_role and not User.query.filter_by(username=username).first():
                user = User(
                    username=username,
                    last_name=f'Пользователь{i}',
                    first_name='Тестовый',
                    role_id=user_role.id
                )
                user.set_password(username)
                db.session.add(user)
        
        db.session.commit()
    
    app.run(debug=True) 