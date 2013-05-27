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
from flask import render_template, request, redirect, url_for, flash, Response, g
from flask.ext.login import login_required, login_user, logout_user, current_user
from reportstool import app, login_manager, User, db

import urllib
import urllib2
import json
import os
import base64
import psycopg2

@app.route('/')
@login_required
def index():
    return render_template("index.html")

@app.route('/new')
@login_required
def new():
    return render_template("new.html")

# Login/logout-related views
@app.route('/login')
def login():
    try:
        ip = request.environ['HTTP_X_FORWARDED_FOR'].split(',')[-1].strip()
    except KeyError:
        ip = request.environ['REMOTE_ADDR']
    rand = base64.urlsafe_b64encode(os.urandom(30))

    cur = db.cursor()
    cur.execute("INSERT INTO csrf (csrf, ip) VALUES (%(csrf)s, %(ip)s)", {'csrf': rand, 'ip': ip})
    db.commit()
    cur.close()

    return render_template("login.html", client_id=app.config['OAUTH_CLIENT_ID'], redirect_uri=app.config['OAUTH_REDIRECT_URI'], csrf=rand)

@app.route('/internal/oauth')
def oauth_callback():
    error = request.args.get('error')
    if not error:
        try:
            ip = request.environ['HTTP_X_FORWARDED_FOR'].split(',')[-1].strip()
        except KeyError:
            ip = request.environ['REMOTE_ADDR']
        csrf = request.args.get('state')
        cur = db.cursor()
        cur.execute('SELECT ip from csrf WHERE csrf = %s', [csrf])
        try:
            row = cur.fetchone()
            if row[0] != ip:
                raise psycopg2.ProgrammingError()
            else:
                cur.execute('DELETE FROM csrf WHERE csrf = %s', [csrf])
                db.commit()
        except psycopg2.ProgrammingError:
            flash('csrf failure')
            return render_template("login.html", client_id=app.config['OAUTH_CLIENT_ID'], redirect_uri=app.config['OAUTH_REDIRECT_URI'], csrf='')
        finally:
            cur.close()

        code = request.args.get('code')
        username = check_mb_account(code)
        if username:
            login_user(User(username))
            flash("Logged in!")
            return redirect(request.args.get("next") or url_for("index"))
        else:
            flash('Could not find username, please try again.')
    else:
        flash('There was an error: ' + error)
    return render_template("login.html", client_id=app.config['OAUTH_CLIENT_ID'], redirect_uri=app.config['OAUTH_REDIRECT_URI'], csrf='')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.")
    return redirect(url_for("index"))

def check_mb_account(auth_code):
    url = 'https://musicbrainz.org/oauth2/token'
    data = urllib.urlencode({'grant_type': 'authorization_code',
                             'code': auth_code,
                             'client_id': app.config['OAUTH_CLIENT_ID'],
                             'client_secret': app.config['OAUTH_CLIENT_SECRET'],
                             'redirect_uri': app.config['OAUTH_REDIRECT_URI']})
    json_data = json.load(urllib2.urlopen(url, data))

    url = 'https://beta.musicbrainz.org/oauth2/userinfo'
    opener = urllib2.build_opener()
    opener.addheaders = [('Authorization', 'Bearer ' + json_data['access_token'])]
    try:
        userdata = json.load(opener.open(url, timeout=5))
        return userdata['sub']
    except StandardError:
        return None
