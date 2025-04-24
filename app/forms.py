# app/forms.py

from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, DateField, SelectField, BooleanField, PasswordField, MultipleFileField
from wtforms.validators import DataRequired, Optional

class BlogForm(FlaskForm):
    title       = StringField('Title', validators=[DataRequired()])
    body        = TextAreaField('Content', validators=[DataRequired()])
    date_posted = DateField('Date', validators=[DataRequired()])
    category    = SelectField(
                     'Category',
                     choices=[
                       ('personal','Personal'),
                       ('professional','Professional'),
                       ('private','Private')
                     ],
                     validators=[DataRequired()]
                   )
    is_private  = BooleanField('Private Post?')
    password    = PasswordField('Password (if private)', validators=[Optional()])
    images      = MultipleFileField('Upload Images', validators=[Optional()])
