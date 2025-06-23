from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, DateField, IntegerField, FileField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, Length, ValidationError
from flask_wtf.file import FileRequired, FileAllowed
from datetime import date

class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')

class EventForm(FlaskForm):
    title = StringField('Название', validators=[DataRequired(), Length(min=3, max=100)])
    description = TextAreaField('Описание', validators=[DataRequired()])
    date = DateField('Дата', validators=[DataRequired()])
    location = StringField('Место проведения', validators=[DataRequired(), Length(max=200)])
    volunteers_needed = IntegerField('Требуемое количество волонтёров', validators=[DataRequired()])
    image = FileField('Изображение', validators=[
        FileRequired(),
        FileAllowed(['jpg', 'png', 'jpeg'], 'Разрешены только изображения!')
    ])

    def validate_date(self, field):
        if field.data < date.today():
            raise ValidationError('Дата не может быть в прошлом')

class RegistrationForm(FlaskForm):
    contact_info = StringField('Контактная информация', validators=[DataRequired(), Length(max=200)])
    submit = SubmitField('Отправить заявку') 