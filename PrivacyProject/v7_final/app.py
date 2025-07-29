from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory, make_response
from config import Config
from models import db, User, Patient, Diagnosis, FileUpload
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from encryption import abe, knn, dynamic_sse
import os
from werkzeug.utils import secure_filename
import pdfkit
from flask import Response
from weasyprint import HTML
import base64


app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('home/index.html')

@app.route('/test')
def test():
    return render_template('home/index.html')

@app.route('/print_diagnosis/<int:diagnosis_id>')
@login_required
def print_diagnosis(diagnosis_id):
    diagnosis = Diagnosis.query.get_or_404(diagnosis_id)
    return render_template('print_diagnosis.html', diagnosis=diagnosis)



def get_base64_image(filepath):
    """Read an image file and return a base64-encoded string."""
    with open(filepath, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode('utf-8')

@app.route('/export_pdf_patient/<int:patient_id>')
def export_pdf_patient(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    decrypted_info = abe.abe_decrypt(patient.encrypted_info, user_attributes="doctor") if patient.encrypted_info else "N/A"

    diagnoses_list = []
    for diag in patient.diagnoses:
        decrypted_diag = abe.abe_decrypt(diag.encrypted_diagnosis, user_attributes="doctor")
        diagnoses_list.append({
            'id': diag.id,
            'diagnosis': decrypted_diag,
            'files': diag.files
        })
    if patient.profile_photo:
        photo_path = os.path.join(app.config['UPLOAD_FOLDER'], patient.profile_photo)
        try:
            patient.profile_photo_base64 = get_base64_image(photo_path)
        except Exception as e:
            patient.profile_photo_base64 = None
            print("Error encoding image:", e)
    else:
        patient.profile_photo_base64 = None
    
    html = render_template('pdf_template.html', patient=patient, decrypted_info=decrypted_info, diagnoses=diagnoses_list)
    pdf = HTML(string=html).write_pdf()
    
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'inline; filename=patient_{patient_id}.pdf'
    
    return response

@app.route('/print_patient/<int:patient_id>')
@login_required
def print_patient(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    decrypted_info = abe.abe_decrypt(patient.encrypted_info, user_attributes="doctor") if patient.encrypted_info else ""

    diagnoses = []
    for diag in patient.diagnoses:
        decrypted_diag = abe.abe_decrypt(diag.encrypted_diagnosis, user_attributes="doctor")
        diagnoses.append({
            'id': diag.id,
            'diagnosis': decrypted_diag,
            'files': diag.files
        })
    return render_template('print_patient.html', patient=patient, decrypted_info=decrypted_info, diagnoses=diagnoses)



@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if current_user.role != 'manager':
        flash("Unauthorized access: Only managers can add new users.")
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists!')
            return redirect(url_for('add_user'))
        
        new_user = User(username=username, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('New user added successfully!')
        return redirect(url_for('dashboard'))
    
    return render_template('add_user.html')


    
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists!')
            return redirect(url_for('register'))
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method=='POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials!')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!')
    return redirect(url_for('login'))
@app.route('/dashboard')
@login_required
def dashboard():
    patients = Patient.query.all()
    return render_template('dashboard.html', patients=patients)
@app.route('/add_patient', methods=['GET', 'POST'])
@login_required
def add_patient():
    if request.method == 'POST':
        patient_name = request.form.get('patient_name')
        patient_info = request.form.get('patient_info')
        encrypted_info = abe.abe_encrypt(patient_info, attributes="doctor") if patient_info else ""

        profile_photo_filename = None
        if 'profile_photo' in request.files:
            photo = request.files['profile_photo']
            if photo and photo.filename:
                filename = secure_filename(photo.filename)
                photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                profile_photo_filename = filename
        
        new_patient = Patient(
            name=patient_name, 
            encrypted_info=encrypted_info, 
            profile_photo=profile_photo_filename
        )
        db.session.add(new_patient)
        db.session.commit()
        flash("Patient record added successfully!")
        return redirect(url_for('dashboard'))
    return render_template('add_patient.html')
@app.route('/patient/<int:patient_id>')
@login_required
def patient_detail(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    decrypted_info = abe.abe_decrypt(patient.encrypted_info, user_attributes="doctor") if patient.encrypted_info else ""
    diagnoses = []
    for diag in patient.diagnoses:
        decrypted_diag = abe.abe_decrypt(diag.encrypted_diagnosis, user_attributes="doctor")
        diagnoses.append({
            'id': diag.id,
            'diagnosis': decrypted_diag,
            'files': diag.files
        })
    return render_template('patient_detail.html', patient=patient, decrypted_info=decrypted_info, diagnoses=diagnoses)
@app.route('/add_diagnosis/<int:patient_id>', methods=['GET', 'POST'])
@login_required
def add_diagnosis(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    if request.method == 'POST':
        diagnosis_data = request.form.get('diagnosis_data')
        encrypted_diagnosis = abe.abe_encrypt(diagnosis_data, attributes="doctor")
        keywords = diagnosis_data.split()
        encrypted_keywords = dynamic_sse.encrypt_keywords(keywords)
        diagnosis = Diagnosis(patient_id=patient.id, encrypted_diagnosis=encrypted_diagnosis, keywords=encrypted_keywords)
        db.session.add(diagnosis)
        db.session.commit()
        if 'files' in request.files:
            uploaded_files = request.files.getlist("files")
            for file in uploaded_files:
                if file and file.filename:
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    file_record = FileUpload(filename=filename, file_path=file_path, diagnosis_id=diagnosis.id)
                    db.session.add(file_record)
            db.session.commit()
        
        flash("Diagnosis record added successfully!")
        return redirect(url_for('patient_detail', patient_id=patient.id))
    return render_template('add_diagnosis.html', patient=patient)
@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
@app.route('/search_patient', methods=['GET', 'POST'])
@login_required
def search_patient():
    if request.method == 'POST':
        search_type = request.form.get("search_type")
        query = request.form.get("query")
        results = []
        
        if search_type == 'id':
            try:
                patient = Patient.query.filter_by(id=int(query)).first()
                if patient:
                    decrypted_info = abe.abe_decrypt(patient.encrypted_info, user_attributes="doctor") if patient.encrypted_info else ""
                    results.append({
                        'id': patient.id,
                        'name': patient.name,
                        'info': decrypted_info
                    })
            except ValueError:
                flash("Invalid ID format. Please enter a numeric ID.")
        
        elif search_type == 'name':
            patients = Patient.query.filter(Patient.name.ilike(f"%{query}%")).all()
            for patient in patients:
                decrypted_info = abe.abe_decrypt(patient.encrypted_info, user_attributes="doctor") if patient.encrypted_info else ""
                results.append({
                    'id': patient.id,
                    'name': patient.name,
                    'info': decrypted_info
                })
        else:
            flash("Invalid search type selected.")
            return redirect(url_for('search_patient'))

        if not results:
            flash("No matching patients found.")
        return render_template('search_patient_results.html', patients=results, query=query, search_type=search_type)
    return render_template('search_patient.html')
@app.route('/search_diagnosis', methods=['GET', 'POST'])
@login_required
def search_diagnosis():
    if request.method == 'POST':
        keyword = request.form.get('keyword')
        search_token = dynamic_sse.generate_search_token(keyword)
        matching_records = []
        all_diagnoses = Diagnosis.query.all()
        for diag in all_diagnoses:
            if diag.keywords and dynamic_sse.search_in_keywords(diag.keywords, search_token):
                matching_records.append((diag, [1, 2, 3]))
        query_vector = [1, 2, 3]
        top_records = knn.knn_search(query_vector, matching_records, k=3)
        results = []
        for diag in top_records:
            decrypted_diag = abe.abe_decrypt(diag.encrypted_diagnosis, user_attributes="doctor")
            results.append({
                'id': diag.id,
                'diagnosis': decrypted_diag,
                'patient_id': diag.patient_id,
                'files': diag.files
            })
        if not results:
            flash("No matching diagnosis records found.")
        return render_template('search_diagnosis_results.html', results=results, keyword=keyword)
    return render_template('search_diagnosis.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)