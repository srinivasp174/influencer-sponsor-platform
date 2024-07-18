from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from config import Config
from flask_restful import Api
from flask_migrate import Migrate


app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
api = Api(app)

import models
import routes
import api_routes

if __name__ == '__main__':
    app.run(debug=True)
