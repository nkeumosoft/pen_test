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


class NmapScanForm(FlaskForm):

    host = StringField('Check Your Host', validators=[validators.DataRequired(), Length(min=10, max=255)])
    start_port = IntegerField()
    end_port = IntegerField()

    submit = SubmitField('Scan')
