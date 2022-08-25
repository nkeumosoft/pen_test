import os

from flask import Flask
from flask_admin import Admin
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

db = SQLAlchemy()
migrate = Migrate()


def create_app(script_info=None):
    # instantiate the app
    app = Flask(__name__)
    app_settings = os.getenv('APP_SETTINGS')
    app.config.from_object(app_settings)

    # init data base
    db.init_app(app)
    migrate.init_app(app, db)

    # init admin
    admin = Admin(app, name='Penetration Testing Tool', template_mode='bootstrap3')

    app.shell_context_processor({'app': app, 'db': db})
    return app
