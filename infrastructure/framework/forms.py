from flask_wtf import FlaskForm
from wtforms import IntegerField, StringField, SubmitField, validators
from wtforms.validators import Length


class WebsiteForm(FlaskForm):
    url = StringField('Url', description='Website url', validators=[validators.input_required()])
    name = StringField('Name', description='Website name')
    submit = SubmitField('Create')


class SearchForm(FlaskForm):
    url = StringField('find your website ', validators=[validators.DataRequired()])
    submit = SubmitField('Submit')


class NcrackScanForm(FlaskForm):

    host = StringField('Check Your Host', validators=[validators.DataRequired(), Length(min=11, max=255)])
    username = StringField('Enter the username', validators=[validators.DataRequired(), Length(min=2, max=255)])
    password = StringField('Check a password', validators=[validators.DataRequired(), Length(min=2, max=255)])

    submit = SubmitField('Scan')

