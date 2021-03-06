# mb-reports-tool
# Copyright (C) 2013 Ian McEwen
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import division, absolute_import
from flask import Flask
from flask.ext.login import LoginManager, UserMixin

import jinja2_highlight

import psycopg2
import psycopg2.extensions
psycopg2.extensions.register_type(psycopg2.extensions.UNICODE)
psycopg2.extensions.register_type(psycopg2.extensions.UNICODEARRAY)

import memcache

from reportstool.config import *

class MyFlask(Flask):
    jinja_options = dict(Flask.jinja_options)
    jinja_options.setdefault('extensions', []).append('jinja2_highlight.HighlightExtension')

app = MyFlask(__name__)
app.config.from_object(__name__)

@app.before_first_request
def setup_logging():
    if not app.debug:
        import logging
        from logging.handlers import RotatingFileHandler
        if app.config['ERROR_LOG']:
            error_fh = RotatingFileHandler(app.config['ERROR_LOG'],
                                           maxBytes=1024 * 1024 * 10,
                                           backupCount=10,
                                           encoding='utf_8')
            error_fh.setLevel(logging.ERROR)
            app.logger.addHandler(error_fh)
        if app.config['WARNING_LOG']:
            warning_fh = RotatingFileHandler(app.config['WARNING_LOG'],
                                             maxBytes=1024 * 1024 * 10,
                                             backupCount=10,
                                             encoding='utf_8')
            warning_fh.setLevel(logging.WARNING)
            app.logger.addHandler(warning_fh)

class User(UserMixin):
    def __init__(self, id):
        self.id = id

login_manager = LoginManager()
login_manager.login_view = "index"

@login_manager.user_loader
def load_user(username):
    return User(username)

login_manager.setup_app(app, add_context_processor=True)

def get_db():
   return psycopg2.connect('host=127.0.0.1 dbname=' + app.config['PGSQL_DB'] + ' user=' + app.config['PGSQL_USER'])

def get_mbdb():
   return psycopg2.connect('host=127.0.0.1 dbname=' + app.config['PGSQL_MB_DB'] + ' user=' + app.config['PGSQL_MB_USER'])

cache = memcache.Client(['127.0.0.1:11211'])

import reportstool.views
