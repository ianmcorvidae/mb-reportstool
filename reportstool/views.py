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
from reportstool import app, login_manager, User, get_db, get_mbdb, cache

import urllib
import urllib2
import json
import os
import base64
import psycopg2
import jinja2
import datetime

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
    if current_user.is_authenticated():
        return render_template("index.html", reports=reports)
    else:
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

        return render_template("index.html", client_id=app.config['OAUTH_CLIENT_ID'], redirect_uri=app.config['OAUTH_REDIRECT_URI'], csrf=rand, reports=reports)

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
        template_headers = request.form['template_headers']
        db = get_db()
        cur = db.cursor()
        cur.execute('INSERT INTO reports (editor, name, sql, template, template_headers) VALUES (%s, %s, %s, %s, %s) RETURNING id', [current_user.id, name, sql, template, template_headers])
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
        return render_template("report/new.html")

@app.route('/report/<reportid>')
def report(reportid):
    report = getreport(reportid, False)
    return render_template("report/info.html", report=report, reportid=reportid)

@app.route('/report/<reportid>/edit', methods=['GET', 'POST'])
@login_required
def report_edit(reportid):
    report = getreport(reportid)
    if request.method == 'POST':
        name = request.form['name']
        sql = request.form['sql']
        template = request.form['template']
        template_headers = request.form['template_headers']
        if (name != report[1] or sql != report[2] or template != report[3] or template_headers != report[4]):
            db = get_db()
            cur = db.cursor()
            cur.execute('UPDATE reports SET name = %s, sql = %s, template = %s, template_headers = %s WHERE id = %s', [name, sql, template, template_headers, reportid])
            if cur.rowcount > 0:
                flash('Successfully updated!')
            else:
                flash('Something went wrong.')
            db.commit()
            cur.close()
            db.close()
            cache.delete_multi([reportid], key_prefix='reportstool:')
        else:
            flash('No changes.')
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
        return render_template("report/edit.html", report=report, extracted=vals, error=error, reportid=reportid)

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
        return render_template("report/delete.html")

@app.route('/report/<reportid>/view')
def report_view(reportid):
    report = getreport(reportid, False)
    error = None
    prerendered = cache.get_multi([reportid], key_prefix='reportstool:')
    if prerendered.get(str(reportid), False):
        vals = prerendered.get(str(reportid))['vals']
        rtime = prerendered.get(str(reportid))['time']
    else:
        mbdb = get_mbdb()
        mbcur = mbdb.cursor()
        try:
            mbcur.execute(report[2])
            vals = [runtemplate(report[3], row) for row in mbcur.fetchall()]
            rtime = datetime.datetime.utcnow()
            try:
                cache.set_multi({str(reportid): {'time': rtime, 'vals': vals}}, time=60*60, key_prefix='reportstool:')
            except: pass # hack since things >1mb fail on rika
        except psycopg2.ProgrammingError, e:
            vals = None
            error = e
        finally:
            mbcur.close()
            mbdb.close()
    return render_template("report/view.html", report=report, extracted=vals, error=error, reportid=reportid, time=rtime)

def getreport(reportid, requireuser=True):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT editor, name, sql, template, template_headers FROM reports WHERE id = %s", [reportid])
    if cur.rowcount > 0:
        report = cur.fetchone()
    else:
        cur.close()
        db.close()
        abort(404)

    if requireuser and report[0] != current_user.id:
        cur.close()
        db.close()
        abort(403)
    cur.close()
    db.close()
    return [process_entry(entry) for entry in report]

def runtemplate(template, row):
    try:
        renderer=jinja2.Template(template)
        return renderer.render(row=[process_entry(entry) for entry in row])
    except Exception, e:
        return e

def process_entry(entry):
    if isinstance(entry, basestring):
        return entry.decode('utf-8')
    else:
        return entry

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
