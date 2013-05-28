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
from flask import render_template, request, redirect, url_for, flash, Response, g, abort
from flask.ext.login import login_required, login_user, logout_user, current_user
from reportstool import app, login_manager, User, get_db, get_mbdb

import urllib
import urllib2
import json
import os
import base64
import psycopg2
import jinja2

@app.route('/')
def index():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT editor, id, name FROM reports ORDER BY editor, id")
    if cur.rowcount > 0:
        reports = cur.fetchall()
    else:
        reports = None
    cur.close()
    db.close()
    return render_template("index.html", reports=reports)

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, name FROM reports WHERE editor = %s", [current_user.id])
    if cur.rowcount > 0:
        reports = cur.fetchall()
    else:
        reports = None
    cur.close()
    db.close()

    return render_template("dashboard.html", reports=reports)

@app.route('/new', methods=['GET', 'POST'])
@login_required
def new():
    if request.method == 'POST':
        name = request.form['name']
        sql = request.form['sql']
        template = request.form['template']
        db = get_db()
        cur = db.cursor()
        cur.execute('INSERT INTO reports (editor, name, sql, template) VALUES (%s, %s, %s, %s) RETURNING id', [current_user.id, name, sql, template])
        if cur.rowcount > 0:
            flash('Successfully inserted!')
            newid = cur.fetchone()[0]
        else:
            flash('Something went wrong.')
            newid = None
        db.commit()
        cur.close()
        db.close()
        if newid:
            return redirect(url_for("report", reportid=newid))
        else:
            return redirect(url_for('dashboard'))
    else:
        return render_template("new.html")

@app.route('/report/<reportid>', methods=['GET', 'POST'])
@login_required
def report(reportid):
    report = getreport(reportid)
    if request.method == 'POST':
        name = request.form['name']
        sql = request.form['sql']
        template = request.form['template']
        db = get_db()
        cur = db.cursor()
        cur.execute('UPDATE reports SET name = %s, sql = %s, template = %s WHERE id = %s', [name, sql, template, reportid])
        if cur.rowcount > 0:
            flash('Successfully updated!')
        else:
            flash('Something went wrong.')
        db.commit()
        cur.close()
        db.close()
        return redirect(url_for("report", reportid=reportid))
    else:
        mbdb = get_mbdb()
        mbcur = mbdb.cursor()
        try:
            mbcur.execute('EXPLAIN ' + report[2])
            vals = mbcur.fetchall()
            error = None
        except psycopg2.ProgrammingError, e:
            vals = None
            error = e
        finally:
            mbcur.close()
            mbdb.close()
        return render_template("report.html", report=report, extracted=vals, error=error, reportid=reportid)

@app.route('/report/<reportid>/delete', methods=['GET', 'POST'])
@login_required
def report_delete(reportid):
    report = getreport(reportid)

    if request.method == 'POST' and request.form['confirm'] == 'on':
        db = get_db()
        cur = db.cursor()
        cur.execute('DELETE FROM reports WHERE id = %s', [reportid])
        if cur.rowcount > 0:
            flash('Successfully deleted!')
        else:
            flash('Something went wrong.')
        db.commit()
        cur.close()
        db.close()
        return redirect(url_for("dashboard"))
    else:
        return render_template("delete.html")

@app.route('/report/<reportid>/preview')
@login_required
def report_preview(reportid):
    report = getreport(reportid)
    mbdb = get_mbdb()
    mbcur = mbdb.cursor()
    try:
        mbcur.execute(report[2])
        vals = [runtemplate(report[3], row) for row in mbcur.fetchall()]
        error = None
    except psycopg2.ProgrammingError, e:
        vals = None
        error = e
    finally:
        mbcur.close()
        mbdb.close()
    return render_template("reportpreview.html", report=report, extracted=vals, error=error, reportid=reportid)

def getreport(reportid):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT editor, name, sql, template FROM reports WHERE id = %s", [reportid])
    if cur.rowcount > 0:
        report = cur.fetchone()
    else:
        cur.close()
        db.close()
        abort(404)

    if report[0] != current_user.id:
        cur.close()
        db.close()
        abort(403)
    cur.close()
    db.close()
    return report

def runtemplate(template, row):
    try:
        renderer=jinja2.Template(template)
        return renderer.render(row=[entry.decode('utf-8') for entry in row])
    except Exception, e:
        return e

# Login/logout-related views
@app.route('/login')
def login():
    try:
        ip = request.environ['HTTP_X_FORWARDED_FOR'].split(',')[-1].strip()
    except KeyError:
        ip = request.environ['REMOTE_ADDR']
    rand = base64.urlsafe_b64encode(os.urandom(30))

    db = get_db()
    cur = db.cursor()
    cur.execute("INSERT INTO csrf (csrf, ip) VALUES (%(csrf)s, %(ip)s)", {'csrf': rand, 'ip': ip})
    db.commit()
    cur.close()
    db.close()

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
        db = get_db()
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
            db.close()

        code = request.args.get('code')
        username = check_mb_account(code)
        if username:
            login_user(User(username))
            flash("Logged in!")
            return redirect(request.args.get("next") or url_for("dashboard"))
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
