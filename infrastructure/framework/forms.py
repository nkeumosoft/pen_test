from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, validators


class WebsiteForm(FlaskForm):
    url = StringField('Url', description='Website url', validators=[validators.input_required()])
    name = StringField('Name', description='Website name')
    submit = SubmitField('Create')


class SearchForm(FlaskForm):
    url = StringField('find your website ', validators=[validators.DataRequired()])
    submit = SubmitField('Submit')