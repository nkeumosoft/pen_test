import os

from flask import Flask
from flask_admin import Admin
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bootstrap import Bootstrap
from flask import redirect, url_for


db = SQLAlchemy()
migrate = Migrate()


def create_app(script_info=None):
    # instantiate the app
    app = Flask(__name__, template_folder='templates')

    app_settings = os.getenv('APP_SETTINGS')
    app.config.from_object(app_settings)
    app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'
    app.config['SECRET_KEY'] = 'secret'
    app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql:///wordcount"
    # init data base
    db.init_app(app)
    migrate.init_app(app, db)
    Bootstrap(app)
    # init admin
    from infrastructure.framework.views import Anomalies, Vulnerabilities, MyHomeView, NmapScanView
    from infrastructure.framework.views import Home, SqlMapScanView

    admin = Admin(
        app,
        name='Penetration Testing',
        template_mode='bootstrap4',
        index_view=MyHomeView(url='/admin', endpoint='admin', name='Wapiti Scan'))
    # Add administrative views here

    admin.add_view(Home(name='Create Website'))
    # admin.add_view(SearchView())
    admin.add_view(Anomalies())
    admin.add_view(Vulnerabilities())
    admin.add_view(NmapScanView(name="Nmap scan"))
    admin.add_view(SqlMapScanView(name="SqlMap scan"))

    @app.route('/')
    def index():
        return redirect(url_for('admin.index'))

    app.run()

    app.shell_context_processor({'app': app, 'db': db})
    return app

