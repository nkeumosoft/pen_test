from flask import Flask, redirect, render_template, url_for, request
from flask_admin import Admin, BaseView, expose

from infrastructure.framework.forms import WebsiteForm
from infrastructure.framework.views import Home, Vulnerabilities, Anomalies

app = Flask(__name__, template_folder='infrastructure/framework/templates')

# set optional bootswatch theme
app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'
app.config['SECRET_KEY'] = 'secret'
admin = Admin(app, name='Penetration Testing Tool', template_mode='bootstrap4', url='/admin')
# Add administrative views here
admin.add_view(Home())
admin.add_view(Vulnerabilities())
admin.add_view(Anomalies())


with app.app_context():

    app.run()
