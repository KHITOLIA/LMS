"""
DASHBOARD — full-featured, optimized single-file app (fixed upload/serve issues)

Notes:
- Fixed: serve_recording route so url_for('serve_recording', ...) builds correctly.
- Fixed: upload/download paths (use string paths for send_from_directory).
- Ensures upload folders exist before saving.
- Added admin-protected upload page and unified upload behaviour.
- Keep debug=True for local troubleshooting; set False in production.

Run: python lms.py
Install: pip install flask flask_sqlalchemy
"""
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os
import pathlib
from datetime import datetime
from math import ceil

BASE_DIR = pathlib.Path(__file__).parent.resolve()
UPLOAD_ROOT = BASE_DIR / 'uploads'
TEMPLATES_DIR = BASE_DIR / 'templates'
DB_PATH = BASE_DIR / 'lms.db'

SECRET_KEY = os.environ.get('LMS_SECRET_KEY', 'dev-secret-key')
ALLOWED_EXTENSIONS = {'mp4', 'mkv', 'webm', 'wav', 'mp3', 'ogg'}
MAX_CONTENT_LENGTH = 1024 * 1024 * 1024  # 1 GB

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# set UPLOAD_FOLDER as a string path for compatibility with send_from_directory
app.config['UPLOAD_FOLDER'] = str(UPLOAD_ROOT)

db = SQLAlchemy(app)

# ---------------- Models ----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)
    role = db.Column(db.String(20), default='student')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    enrollments = db.relationship('Enrollment', backref='user', cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Batch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    recordings = db.relationship('Recording', backref='batch', cascade='all, delete-orphan')
    enrollments = db.relationship('Enrollment', backref='batch', cascade='all, delete-orphan')

class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    batch_id = db.Column(db.Integer, db.ForeignKey('batch.id'), index=True)
    enrolled_at = db.Column(db.DateTime, default=datetime.utcnow)

class Recording(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(500), nullable=False)
    original_name = db.Column(db.String(500), nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)
    batch_id = db.Column(db.Integer, db.ForeignKey('batch.id'))
    notes = db.Column(db.Text, nullable=True)

# ---------------- Helpers ----------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def ensure_structure():
    # ensure uploads and templates directory exist
    UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
    create_file_if_missing(TEMPLATES_DIR / 'layout.html', layout_html)
    create_file_if_missing(TEMPLATES_DIR / 'index.html', index_html)
    create_file_if_missing(TEMPLATES_DIR / 'register.html', register_html)
    create_file_if_missing(TEMPLATES_DIR / 'login.html', login_html)
    create_file_if_missing(TEMPLATES_DIR / 'admin_dashboard.html', admin_dashboard_html)
    create_file_if_missing(TEMPLATES_DIR / 'student_dashboard.html', student_dashboard_html)
    create_file_if_missing(TEMPLATES_DIR / 'batch.html', batch_html)
    create_file_if_missing(TEMPLATES_DIR / 'upload_recording.html', upload_recording_html)
    create_file_if_missing(TEMPLATES_DIR / 'student_batches.html', student_batches_html)
    create_file_if_missing(TEMPLATES_DIR / 'batch_enrollments.html', batch_enrollments_html)
    create_file_if_missing(TEMPLATES_DIR / 'edit_batch.html', edit_batch_html)
    create_file_if_missing(TEMPLATES_DIR / 'enrollments.html', enrollments_html)

def create_file_if_missing(path: pathlib.Path, content: str):
    if not path.exists():
        path.write_text(content, encoding='utf-8')

# ---------------- Templates ----------------
layout_html = '''<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>DASHBOARD</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
      body { background:#f6f8fb; color:#212529; font-family:'Segoe UI', sans-serif; }
      .card-ghost { border:0; box-shadow:0 2px 10px rgba(0,0,0,0.08); border-radius:0.5rem; margin-bottom:1rem; }
      .nav-brand { font-weight:700; letter-spacing:0.5px; color:#0d6efd; }
      .small-muted { color:#6c757d; font-size:0.9rem; }
      .btn-primary { background-color:#0d6efd; border-color:#0d6efd; }
      .btn-primary:hover { background-color:#0b5ed7; border-color:#0a58ca; }
      a { text-decoration:none; }
      a:hover { text-decoration:underline; }
      @media (max-width: 768px) { .navbar-nav { text-align:center; } }
      .dark-mode { background:#212529; color:white; }
      .dark-mode .card { background:#2c2c2c; color:white; }
      .dark-mode a { color:#0d6efd; }
    </style>
  </head>
  <body>
  <nav class="navbar navbar-expand-lg navbar-white bg-white shadow-sm mb-4">
    <div class="container">
      <a class="navbar-brand nav-brand" href="{{ url_for('index') }}">DASHBOARD</a>
      <div class="collapse navbar-collapse">
        <ul class="navbar-nav ms-auto">
        {% if current_user() %}
          <li class="nav-item"><a class="nav-link" href="{{ url_for('dashboard') }}">Dashboard</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('logout') }}">Logout</a></li>
        {% else %}
          <li class="nav-item"><a class="nav-link" href="{{ url_for('login') }}">Login</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('register') }}">Register</a></li>
        {% endif %}
        </ul>
      </div>
    </div>
  </nav>
  <div class="container mb-5">
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for category, msg in messages %}
          <div class="alert alert-{{ category }}">{{ msg }}</div>
        {% endfor %}
      {% endif %}
    {% endwith %}
    {% block content %}{% endblock %}
  </div>
  <button class="btn btn-secondary position-fixed bottom-0 end-0 m-3" onclick="document.body.classList.toggle('dark-mode');">Toggle Dark Mode</button>
  </body>
</html>'''

index_html = '''{% extends 'layout.html' %}
{% block content %}
<div class="row">
  <div class="col-md-8">
    <div class="row">
      {% for b in batches %}
      <div class="col-md-6 mb-3">
        <div class="card card-ghost p-3">
          <h5>{{ b.name }}</h5>
          <p class="small-muted">{{ b.description or '' }}</p>
          <a class="btn btn-sm btn-outline-primary" href="{{ url_for('view_batch', batch_id=b.id) }}">View</a>
        </div>
      </div>
      {% endfor %}
    </div>
  </div>
  <div class="col-md-4">
    <div class="card p-3">
      <h5>Quick Actions</h5>
      {% if current_user() and current_user().role=='admin' %}
        <a class="btn btn-primary w-100 mb-2" href="{{ url_for('dashboard') }}">Open Admin Dashboard</a>
      {% else %}
        <p>Login as admin to manage batches and students.</p>
      {% endif %}
    </div>
  </div>
</div>
{% endblock %}'''

register_html = '''{% extends 'layout.html' %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-6">
    <div class="card p-4 card-ghost">
      <h4>Create account</h4>
      <form method="post" action="{{ url_for('register') }}">
        <div class="mb-2"><input class="form-control" name="name" placeholder="Full name" required></div>
        <div class="mb-2"><input class="form-control" name="email" placeholder="Email" type="email" required></div>
        <div class="mb-2"><input class="form-control" name="password" placeholder="Password" type="password" required></div>
        <div class="mb-2">
          <select class="form-select" name="role">
            <option value="student" selected>Student</option>
            <option value="admin">Admin</option>
          </select>
        </div>
        <button class="btn btn-success w-100">Register</button>
      </form>
      <p class="small-muted mt-2 text-center">Already registered? <a href="{{ url_for('login') }}">Login here</a>.</p>
    </div>
  </div>
</div>
{% endblock %}'''

login_html = '''{% extends 'layout.html' %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-6">
    <div class="card p-4 card-ghost">
      <h4>Login</h4>
      <form method="post" action="{{ url_for('login') }}">
        <div class="mb-2"><input class="form-control" name="email" placeholder="Email" type="email" required></div>
        <div class="mb-2"><input class="form-control" name="password" placeholder="Password" type="password" required></div>
        <button class="btn btn-primary w-100">Login</button>
      </form>
      <p class="small-muted mt-2 text-center">Not registered? <a href="{{ url_for('register') }}">Create an account</a>.</p>
    </div>
  </div>
</div>
{% endblock %}'''

admin_dashboard_html = '''{% extends 'layout.html' %}
{% block content %}
<h3>Admin Dashboard</h3>
<div class="row">
  <div class="col-md-6">
    <div class="card card-ghost p-3 mb-3">
      <h5>Create Batch</h5>
      <form method="post" action="{{ url_for('create_batch') }}">
        <div class="mb-2"><input class="form-control" name="name" placeholder="Batch name" required></div>
        <div class="mb-2"><textarea class="form-control" name="description" placeholder="Description"></textarea></div>
        <button class="btn btn-primary w-100">Create</button>
      </form>
    </div>
    <div class="card card-ghost p-3 mb-3">
      <h5>Enroll Student</h5>
      <form method="post" action="{{ url_for('enroll_student') }}">
        <div class="mb-2">
          <select class="form-select" name="user_id" required>
            <option value="">Select student</option>
            {% for u in students %}<option value="{{ u.id }}">{{ u.name }} ({{ u.email }})</option>{% endfor %}
          </select>
        </div>
        <div class="mb-2">
          <select class="form-select" name="batch_id" required>
            <option value="">Select batch</option>
            {% for b in batches %}<option value="{{ b.id }}">{{ b.name }}</option>{% endfor %}
          </select>
        </div>
        <button class="btn btn-success w-100">Enroll</button>
      </form>
    </div>
  </div>
  <div class="col-md-6">
    <div class="card card-ghost p-3 mb-3">
      <h5>All Batches</h5>
      <ul class="list-group">
        {% for b in batches %}
        <li class="list-group-item d-flex justify-content-between align-items-center">
          <div><strong>{{ b.name }}</strong><br><small class="small-muted">{{ b.description or '' }}</small></div>
          <div>
            <a class="btn btn-sm btn-outline-primary" href="{{ url_for('view_batch', batch_id=b.id) }}">Open</a>
            <a class="btn btn-sm btn-outline-danger" href="{{ url_for('delete_batch', batch_id=b.id) }}" onclick="return confirm('Delete batch?')">Delete</a>
          </div>
        </li>
        {% endfor %}
      </ul>
    </div>
  </div>
</div>
{% endblock %}'''

student_dashboard_html = '''{% extends 'layout.html' %}
{% block content %}
<h3>Student Dashboard</h3>
<div class="row">
  <div class="col-md-8">
    <div class="card card-ghost p-3 mb-3">
      <h5>Your Batches</h5>
      <div class="list-group">
        {% for e in enrollments %}
        <a class="list-group-item list-group-item-action" href="{{ url_for('view_batch', batch_id=e.batch.id) }}">{{ e.batch.name }} <small class="small-muted">- enrolled {{ e.enrolled_at.strftime('%Y-%m-%d') }}</small></a>
        {% endfor %}
      </div>
    </div>
  </div>
</div>
{% endblock %}'''

# Updated batch template to include video playback using serve_recording endpoint
batch_html = '''{% extends 'layout.html' %}
{% block content %}
<h3>Batch: {{ batch.name }}</h3>
<p class="small-muted">{{ batch.description }}</p>
<hr>

{% if is_admin() %}
<div class="card p-3 mb-3">
  <h5>Upload Recording</h5>
  <form method="post" action="{{ url_for('upload', batch_id=batch.id) }}" enctype="multipart/form-data">
    <div class="mb-2"><input type="file" name="file" class="form-control" required></div>
    <div class="mb-2"><input class="form-control" name="notes" placeholder="Notes (optional)"></div>
    <button class="btn btn-success">Upload</button>
  </form>
  <a class="btn btn-outline-secondary mt-2" href="{{ url_for('upload_page', batch_id=batch.id) }}">Open upload page</a>
</div>
{% endif %}

<h5>Recordings</h5>
<div class="card p-3">
  {% if recordings %}
    <div class="table-responsive">
      <table class="table table-striped">
        <thead><tr><th>#</th><th>Name</th><th>Uploaded</th><th>Notes</th><th>Preview</th><th>Actions</th></tr></thead>
        <tbody>
          {% for r in recordings %}
          <tr>
            <td>{{ loop.index }}</td>
            <td>{{ r.original_name }}</td>
            <td>{{ r.upload_time.strftime('%Y-%m-%d %H:%M') }}</td>
            <td>{{ r.notes or '' }}</td>
            <td>
              {% set ext = r.filename.rsplit('.',1)[-1].lower() %}
              {% if ext in ['mp4','webm','mkv'] %}
                <video width="240" controls>
                  <source src="{{ url_for('serve_recording', batch_id=batch.id, filename=r.filename) }}" type="video/{{ ext if ext!='mkv' else 'mp4' }}">
                  Your browser does not support the video tag.
                </video>
              {% else %}
                <a href="{{ url_for('serve_recording', batch_id=batch.id, filename=r.filename) }}" target="_blank">Open</a>
              {% endif %}
            </td>
            <td>
              <a class="btn btn-sm btn-outline-primary" href="{{ url_for('download', batch_id=batch.id, filename=r.filename) }}">Download</a>
              {% if is_admin() %}
                <a class="btn btn-sm btn-outline-danger" href="{{ url_for('delete_recording', rec_id=r.id) }}" onclick="return confirm('Delete recording?')">Delete</a>
              {% endif %}
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  {% else %}
    <p>No recordings yet.</p>
  {% endif %}
</div>
{% endblock %}'''  # end of batch_html

# small templates used by admin actions (upload page, student batches etc.)
upload_recording_html = '''{% extends 'layout.html' %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-7">
    <div class="card p-4 card-ghost">
      <h4>Upload Recording to {{ batch.name }}</h4>
      <form method="post" action="{{ url_for('upload', batch_id=batch.id) }}" enctype="multipart/form-data">
        <div class="mb-3">
          <label class="form-label">Select File</label>
          <input type="file" name="file" class="form-control" required>
        </div>
        <div class="mb-3">
          <label class="form-label">Notes (Optional)</label>
          <input type="text" name="notes" class="form-control" placeholder="Any description for this recording">
        </div>
        <button class="btn btn-success w-100">Upload</button>
      </form>
      <a class="btn btn-outline-secondary mt-2" href="{{ url_for('view_batch', batch_id=batch.id) }}">Back to batch</a>
    </div>
  </div>
</div>
{% endblock %}'''

student_batches_html = '''{% extends 'layout.html' %}
{% block content %}
<h3>Batches for {{ student.name }}</h3>
<ul class="list-group mt-3">
  {% for e in enrollments %}
    <li class="list-group-item d-flex justify-content-between align-items-center">
      <div>
        <strong>{{ e.batch.name }}</strong><br>
        <small class="small-muted">{{ e.batch.description or '' }}</small>
      </div>
      <div><small class="small-muted">Enrolled: {{ e.enrolled_at.strftime('%Y-%m-%d') }}</small></div>
    </li>
  {% else %}
    <li class="list-group-item">Student not enrolled in any batches.</li>
  {% endfor %}
</ul>
<a class="btn btn-secondary mt-3" href="{{ url_for('dashboard') }}">Back to dashboard</a>
{% endblock %}'''

batch_enrollments_html = '''{% extends 'layout.html' %}
{% block content %}
<h3>Enrollments — {{ batch.name }}</h3>
<table class="table">
  <thead><tr><th>#</th><th>Student</th><th>Email</th><th>Enrolled At</th><th>Action</th></tr></thead>
  <tbody>
    {% for e in enrollments %}
      <tr>
        <td>{{ loop.index }}</td>
        <td>{{ e.user.name }}</td>
        <td>{{ e.user.email }}</td>
        <td>{{ e.enrolled_at.strftime('%Y-%m-%d') }}</td>
        <td>
          <a class="btn btn-sm btn-outline-danger" href="{{ url_for('delete_enrollment', enroll_id=e.id) }}" onclick="return confirm('Remove this student from batch?')">Remove</a>
        </td>
      </tr>
    {% else %}
      <tr><td colspan="5">No enrollments yet.</td></tr>
    {% endfor %}
  </tbody>
</table>
<a class="btn btn-secondary" href="{{ url_for('dashboard') }}">Back</a>
{% endblock %}'''

edit_batch_html = '''{% extends 'layout.html' %}
{% block content %}
<h3>Edit Batch</h3>
<form method="post" action="{{ url_for('edit_batch', batch_id=batch.id) }}">
  <div class="mb-2"><input class="form-control" name="name" value="{{ batch.name }}" required></div>
  <div class="mb-2"><textarea class="form-control" name="description">{{ batch.description or '' }}</textarea></div>
  <button class="btn btn-primary">Save</button>
  <a class="btn btn-secondary" href="{{ url_for('dashboard') }}">Cancel</a>
</form>
{% endblock %}'''

enrollments_html = '''{% extends 'layout.html' %}
{% block content %}
<h3>All Enrollments</h3>
<table class="table">
  <thead><tr><th>#</th><th>Student</th><th>Email</th><th>Batch</th><th>Enrolled At</th></tr></thead>
  <tbody>
    {% for e in enrollments %}
      <tr>
        <td>{{ loop.index }}</td>
        <td>{{ e.user.name }}</td>
        <td>{{ e.user.email }}</td>
        <td>{{ e.batch.name }}</td>
        <td>{{ e.enrolled_at.strftime('%Y-%m-%d') }}</td>
      </tr>
    {% else %}
      <tr><td colspan="5">No enrollments.</td></tr>
    {% endfor %}
  </tbody>
</table>
{% endblock %}'''

# ---------------- Context helpers ----------------
@app.context_processor
def inject_helpers():
    def current_user():
        uid = session.get('user_id')
        if not uid:
            return None
        return User.query.get(uid)
    def is_admin():
        u = None
        uid = session.get('user_id')
        if uid:
            u = User.query.get(uid)
        return u and u.role == 'admin'
    return dict(current_user=current_user, is_admin=is_admin)

# ---------------- Routes ----------------
@app.route('/')
def index():
    batches = Batch.query.order_by(Batch.created_at.desc()).all()
    return render_template('index.html', batches=batches)

@app.route('/register', methods=['GET','POST'])
def register():
    admin_exists = User.query.filter_by(role='admin').first() is not None

    if request.method=='POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form.get('role','student')

        # Prevent creating another admin
        if role == 'admin' and admin_exists:
            flash('An admin already exists. Cannot create another admin.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered','danger')
            return redirect(url_for('register'))

        u = User(name=name,email=email,role=role)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        flash('Account created. Please login.','success')
        return redirect(url_for('login'))

    return render_template('register.html', admin_exists=admin_exists)


@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        email = request.form['email']
        password = request.form['password']
        u = User.query.filter_by(email=email).first()
        if not u or not u.check_password(password):
            flash('Invalid credentials','danger')
            return redirect(url_for('login'))
        session['user_id'] = u.id
        flash('Logged in','success')
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id',None)
    flash('Logged out','info')
    return redirect(url_for('index'))

@app.route('/admin')
def admin_dashboard():
    if not session.get('user_id'):
        abort(403)
    u = User.query.get(session['user_id'])
    if not u or u.role != 'admin':
        abort(403)
    batches = Batch.query.order_by(Batch.created_at.desc()).all()
    students = User.query.filter(User.role == 'student').all()
    return render_template('admin_dashboard.html', batches=batches, students=students)

# Admin: view all enrollments
@app.route('/enrollments')
def view_enrollments():
    if not session.get('user_id'):
        abort(403)
    u = User.query.get(session['user_id'])
    if not u or u.role != 'admin':
        abort(403)
    enrollments = Enrollment.query.join(User).join(Batch).order_by(Enrollment.enrolled_at.desc()).all()
    return render_template('enrollments.html', enrollments=enrollments)

@app.route('/dashboard')
def dashboard():
    uid = session.get('user_id')
    if not uid:
        flash('Login first','danger')
        return redirect(url_for('login'))
    u = User.query.get(uid)
    if u.role=='admin':
        students = User.query.filter_by(role='student').all()
        batches = Batch.query.all()
        return render_template('admin_dashboard.html', students=students, batches=batches)
    else:
        enrollments = Enrollment.query.filter_by(user_id=u.id).all()
        return render_template('student_dashboard.html', enrollments=enrollments)

@app.route('/batch/<int:batch_id>')
def view_batch(batch_id):
    batch = Batch.query.get_or_404(batch_id)
    recordings = Recording.query.filter_by(batch_id=batch.id).order_by(Recording.upload_time.desc()).all()
    return render_template('batch.html', batch=batch, recordings=recordings)

@app.route('/enrollment/delete/<int:enroll_id>')
def delete_enrollment(enroll_id):
    if not session.get('user_id'):
        abort(403)
    u = User.query.get(session['user_id'])
    if not u or u.role != 'admin':
        abort(403)
    
    enrollment = Enrollment.query.get_or_404(enroll_id)
    db.session.delete(enrollment)
    db.session.commit()
    flash(f"Student {enrollment.user.name} removed from batch {enrollment.batch.name}", "success")
    
    # Redirect back to the enrollments page
    return redirect(url_for('view_batch_enrollments', batch_id=enrollment.batch_id))

@app.route('/batch/<int:batch_id>/upload', methods=['POST'])
def upload(batch_id):
    # Admin only
    if not inject_helpers()['is_admin']():
        abort(403)
    batch = Batch.query.get_or_404(batch_id)
    file = request.files.get('file')
    notes = request.form.get('notes', '')

    if not file or file.filename == '':
        flash("No file selected", "danger")
        return redirect(url_for('view_batch', batch_id=batch.id))

    if not allowed_file(file.filename):
        flash(f"File type not allowed. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}", "danger")
        return redirect(url_for('view_batch', batch_id=batch.id))

    try:
        # ensure folder exists
        folder = UPLOAD_ROOT / str(batch.id)
        folder.mkdir(parents=True, exist_ok=True)

        filename = secure_filename(file.filename)
        filepath = folder / filename
        # save using string path
        file.save(str(filepath))

        # add record
        r = Recording(filename=filename, original_name=file.filename, batch_id=batch.id, notes=notes)
        db.session.add(r)
        db.session.commit()
        flash('Uploaded successfully','success')
    except Exception as e:
        app.logger.exception("Upload failed")
        flash(f"Error uploading file: {str(e)}", "danger")
    return redirect(url_for('view_batch', batch_id=batch.id))

# Admin upload page (separate GET page for upload)
@app.route('/batch/<int:batch_id>/upload_page')
def upload_page(batch_id):
    if not inject_helpers()['is_admin']():
        abort(403)
    batch = Batch.query.get_or_404(batch_id)
    return render_template('upload_recording.html', batch=batch)

# Serve a recording for inline playback or download (used by video <source> in template)
@app.route('/recordings/<int:batch_id>/<path:filename>')
def serve_recording(batch_id, filename):
    # folder path as string
    folder = os.path.join(app.config['UPLOAD_FOLDER'], str(batch_id))
    filepath = os.path.join(folder, filename)
    if not os.path.exists(filepath):
        abort(404)
    # send without as_attachment so browser may play inline
    return send_from_directory(folder, filename)

# Download endpoint (forces attachment)
@app.route('/uploads/<int:batch_id>/<path:filename>')
def download(batch_id, filename):
    folder = os.path.join(app.config['UPLOAD_FOLDER'], str(batch_id))
    filepath = os.path.join(folder, filename)
    if not os.path.exists(filepath):
        flash('File not found', 'danger')
        return redirect(url_for('view_batch', batch_id=batch_id))
    return send_from_directory(folder, filename, as_attachment=True)

@app.route('/admin/upload/<int:batch_id>', methods=['GET', 'POST'])
def admin_upload_legacy(batch_id):
    """
    Backwards-compatible admin upload route if called directly.
    Uses same logic as /batch/<batch_id>/upload.
    """
    if not inject_helpers()['is_admin']():
        abort(403)
    if request.method == 'POST':
        return upload(batch_id)
    return redirect(url_for('upload_page', batch_id=batch_id))

@app.route('/create_batch', methods=['POST'])
def create_batch():
    if not inject_helpers()['is_admin']():
        abort(403)
    name = request.form['name']
    desc = request.form.get('description')
    if Batch.query.filter_by(name=name).first():
        flash('Batch exists','danger')
        return redirect(url_for('dashboard'))
    b = Batch(name=name, description=desc)
    db.session.add(b)
    db.session.commit()
    flash('Batch created','success')
    return redirect(url_for('dashboard'))

@app.route('/delete_batch/<int:batch_id>')
def delete_batch(batch_id):
    if not inject_helpers()['is_admin']():
        abort(403)
    b = Batch.query.get_or_404(batch_id)
    folder = UPLOAD_ROOT / str(b.id)
    if folder.exists():
        for f in folder.iterdir():
            try:
                f.unlink()
            except Exception:
                app.logger.exception("Failed to delete file %s", f)
        try:
            folder.rmdir()
        except Exception:
            pass
    db.session.delete(b)
    db.session.commit()
    flash('Batch deleted','info')
    return redirect(url_for('dashboard'))

@app.route('/delete_recording/<int:rec_id>')
def delete_recording(rec_id):
    if not inject_helpers()['is_admin']():
        abort(403)
    r = Recording.query.get_or_404(rec_id)
    filepath = UPLOAD_ROOT / str(r.batch_id) / r.filename
    try:
        if filepath.exists():
            filepath.unlink()
    except Exception:
        app.logger.exception("Failed to remove file")
    db.session.delete(r)
    db.session.commit()
    flash('Recording deleted','info')
    return redirect(url_for('view_batch', batch_id=r.batch_id))

@app.route('/edit_batch/<int:batch_id>', methods=['GET', 'POST'])
def edit_batch(batch_id):
    if not session.get('user_id'):
        abort(403)
    u = User.query.get(session['user_id'])
    if not u or u.role != 'admin':
        abort(403)

    batch = Batch.query.get_or_404(batch_id)

    if request.method == 'POST':
        new_name = request.form['name']
        new_desc = request.form.get('description', '')
        
        # Check if another batch has the same name
        existing = Batch.query.filter(Batch.name == new_name, Batch.id != batch.id).first()
        if existing:
            flash('Another batch with this name already exists', 'danger')
            return redirect(url_for('dashboard'))

        batch.name = new_name
        batch.description = new_desc
        db.session.commit()
        flash('Batch updated successfully', 'success')
        return redirect(url_for('dashboard'))

    # GET request: render edit form
    return render_template('edit_batch.html', batch=batch)

@app.route('/batch/<int:batch_id>/enrollments')
def view_batch_enrollments(batch_id):
    if not session.get('user_id'):
        abort(403)
    u = User.query.get(session['user_id'])
    if not u or u.role != 'admin':
        abort(403)
    batch = Batch.query.get_or_404(batch_id)
    enrollments = Enrollment.query.filter_by(batch_id=batch.id).order_by(Enrollment.enrolled_at.desc()).all()
    return render_template('batch_enrollments.html', batch=batch, enrollments=enrollments)

@app.route('/student/<int:user_id>/batches')
def view_student_batches(user_id):
    if not session.get('user_id'):
        abort(403)
    admin = User.query.get(session['user_id'])
    if not admin or admin.role != 'admin':
        abort(403)

    student = User.query.get_or_404(user_id)
    enrollments = Enrollment.query.filter_by(user_id=student.id).join(Batch).all()

    return render_template('student_batches.html', student=student, enrollments=enrollments)

@app.route('/search_student_batches')
def search_student_batches():
    if not session.get('user_id'):
        abort(403)
    admin = User.query.get(session['user_id'])
    if not admin or admin.role != 'admin':
        abort(403)

    query = request.args.get('query', '').strip()
    student = None

    # Search by email first
    if '@' in query:
        student = User.query.filter_by(email=query).first()
    else:
        # Search by enrollment ID (numeric)
        if query.isdigit():
            enrollment = Enrollment.query.get(int(query))
            if enrollment:
                student = enrollment.user

    if not student:
        flash('Student not found', 'danger')
        return redirect(url_for('dashboard'))

    enrollments = Enrollment.query.filter_by(user_id=student.id).join(Batch).all()
    return render_template('student_batches.html', student=student, enrollments=enrollments)

@app.route('/enroll_student', methods=['POST'])
def enroll_student():
    if not inject_helpers()['is_admin']():
        abort(403)
    user_id = request.form.get('user_id')
    batch_id = request.form.get('batch_id')
    if Enrollment.query.filter_by(user_id=user_id, batch_id=batch_id).first():
        flash('Student already enrolled','info')
    else:
        e = Enrollment(user_id=user_id, batch_id=batch_id)
        db.session.add(e)
        db.session.commit()
        flash('Student enrolled','success')
    return redirect(url_for('dashboard'))

# ---------------- Initialize ----------------
if __name__ == '__main__':
    ensure_structure()
    # Run inside application context
    with app.app_context():
        db.create_all()
        # create default admin if not exists
        if not User.query.filter_by(email='admin@lms.com').first():
            admin = User(name='Admin', email='admin@lms.com', role='admin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print('Created default admin: admin@lms.com / admin123')
    # debug True for local testing - set debug=False in production
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
