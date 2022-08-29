import os

from flask import Flask
from flask_admin import Admin
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate


db = SQLAlchemy()
migrate = Migrate()


def create_app(script_info=None):
    # instantiate the app
    app = Flask(__name__, template_folder='templates')

    app_settings = os.getenv('APP_SETTINGS')
    app.config.from_object(app_settings)
    app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'
    app.config['SECRET_KEY'] = 'secret'

    # init data base
    db.init_app(app)
    migrate.init_app(app, db)

    # init admin
    from infrastructure.framework.views import Anomalies, Vulnerabilities
    from infrastructure.framework.views import Home
    admin = Admin(app, name='Penetration Testing', template_mode='bootstrap3', url='/admin')
    # Add administrative views here
    admin.add_view(Home())
    admin.add_view(Anomalies())
    admin.add_view(Vulnerabilities())

    app.run()

    app.shell_context_processor({'app': app, 'db': db})
    return app
