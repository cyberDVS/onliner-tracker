from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, HiddenField, PasswordField
from wtforms.validators import DataRequired, Email


class Item(FlaskForm):
    id = HiddenField('id')
    link = StringField('Item Link', validators=[DataRequired()])
    name = StringField('Item Name', validators=[DataRequired()])
    acceptable_price = StringField('Acceptable Price', validators=[DataRequired()])
    submit = SubmitField()


class Register(FlaskForm):
    login = StringField('Login', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')


class Login(FlaskForm):
    name = StringField('Login or Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')


class ResetPassword(FlaskForm):
    name = StringField('Login or Email', validators=[DataRequired()])
    submit = SubmitField('Reset Password')


class NewPassword(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Reset Password')
