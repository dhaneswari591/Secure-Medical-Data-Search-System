from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='staff')  #  'manager'
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    encrypted_info = db.Column(db.Text, nullable=True)
    profile_photo = db.Column(db.String(256), nullable=True)  
    diagnoses = db.relationship('Diagnosis', backref='patient', lazy=True)


class Diagnosis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=False)
    encrypted_diagnosis = db.Column(db.Text, nullable=False)
    keywords = db.Column(db.Text, nullable=True)
    files = db.relationship('FileUpload', backref='diagnosis', lazy=True)

class FileUpload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256), nullable=False)
    file_path = db.Column(db.String(512), nullable=False)
    diagnosis_id = db.Column(db.Integer, db.ForeignKey('diagnosis.id'), nullable=False)
