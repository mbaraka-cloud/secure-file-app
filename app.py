from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash, g
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail, Message
# Les imports de flask_limiter ont été supprimés afin de retirer les restrictions sur le nombre de téléchargements et de sessions
from config import Config
from models import db, User, File
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from datetime import datetime
import os
import io

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
migrate = Migrate(app, db)

# --- Configuration SMTP (utilisation de SSL sur le port 465) ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465         # Port SSL
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USERNAME'] = 'tsarafarah@gmail.com'
app.config['MAIL_PASSWORD'] = 'uydovounyaltkwjn'  # Mot de passe d'application sans espaces
app.config['MAIL_DEFAULT_SENDER'] = 'tsarafarah@gmail.com'
mail = Mail(app)
# --------------------------------------------------------------

# Définir le dossier uploads en chemin absolu
UPLOAD_FOLDER = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Injecter la classe User dans tous les templates
@app.context_processor
def inject_user():
    from models import User
    return dict(User=User)

# Création des tables et du compte admin par défaut
with app.app_context():
    db.create_all()
    admin = User.query.filter_by(email='admin@example.com').first()
    if not admin:
        admin = User(
            first_name="Admin",
            last_name="User",
            birth_date=datetime(2000, 1, 1),
            email="admin@example.com",
            country="France",
            password_hash=generate_password_hash("adminpassword", method="pbkdf2:sha256"),
            is_admin=True,
            mobile_number="0123456789",  # Exemple de numéro
            security_question="Quel est le nom de votre premier animal ?",
            security_answer_hash=generate_password_hash("Fluffy", method="pbkdf2:sha256")
        )
        db.session.add(admin)
        db.session.commit()
    else:
        admin.is_admin = True
        db.session.commit()

# Extensions autorisées (ajout de "exe")
ALLOWED_EXTENSIONS = {
    'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'tiff',  # Images
    'mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv', 'webm',     # Vidéos
    'mp3', 'wav', 'flac', 'ogg', 'aac', 'm4a',            # Musique
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf', 'odt',  # Documents
    'zip', 'rar', '7z', 'tar', 'gz',                     # Archives
    'exe'  # Applications exécutables
}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Déterminer automatiquement la catégorie du fichier
def auto_assign_category(filename):
    ext = filename.rsplit('.', 1)[1].lower()
    if ext in {'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'tiff'}:
        return 'image'
    elif ext in {'mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv', 'webm'}:
        return 'video'
    elif ext in {'mp3', 'wav', 'flac', 'ogg', 'aac', 'm4a'}:
        return 'musique'
    elif ext in {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf', 'odt'}:
        return 'document'
    elif ext == 'exe':
        return 'application'
    else:
        return 'autre'

### Fonctions de chiffrement / déchiffrement
def generate_key():
    return get_random_bytes(16)

def encrypt_file(file_path, file_name):
    key = generate_key()
    cipher = AES.new(key, AES.MODE_CBC)
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    stored_filename = file_name + ".enc"
    encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
    with open(encrypted_file_path, 'wb') as f:
        f.write(cipher.iv)
        f.write(ciphertext)
    os.remove(file_path)
    return stored_filename, key

def decrypt_file(encrypted_file_path, key):
    with open(encrypted_file_path, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

### Routes de base
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Note : La restriction "5 per hour" a été supprimée
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        else:
            flash("Échec de l'authentification", "danger")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

### Inscription (accessible à tous)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        birth_date = datetime.strptime(request.form['birth_date'], '%Y-%m-%d')
        email = request.form['email']
        country = request.form['country']
        password = request.form['password']
        mobile_number = request.form['mobile_number']
        security_question = request.form['security_question']
        security_answer = request.form['security_answer']
        
        if User.query.filter_by(email=email).first():
            flash("Cet email est déjà utilisé.", "danger")
            return redirect(url_for('register'))
        
        new_user = User(
            first_name=first_name,
            last_name=last_name,
            birth_date=birth_date,
            email=email,
            country=country,
            password_hash=generate_password_hash(password, method="pbkdf2:sha256"),
            mobile_number=mobile_number,
            security_question=security_question,
            security_answer_hash=generate_password_hash(security_answer, method="pbkdf2:sha256")
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Inscription réussie ! Vous pouvez maintenant vous connecter.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

### Gestion des utilisateurs (admin uniquement)
@app.route('/users', methods=['GET'])
def manage_users():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    current_user = User.query.get(session['user_id'])
    if not current_user.is_admin:
        flash("Vous n'avez pas accès à cette page.", "danger")
        return redirect(url_for('dashboard'))
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/users/add', methods=['GET', 'POST'])
def add_user():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    current_user = User.query.get(session['user_id'])
    if not current_user.is_admin:
        flash("Vous n'avez pas les droits pour ajouter des utilisateurs.", "danger")
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        birth_date = datetime.strptime(request.form['birth_date'], '%Y-%m-%d')
        email = request.form['email']
        country = request.form['country']
        password = request.form['password']
        is_admin = 'is_admin' in request.form
        
        if User.query.filter_by(email=email).first():
            flash("Cet email est déjà utilisé.", "warning")
        else:
            new_user = User(
                first_name=first_name,
                last_name=last_name,
                birth_date=birth_date,
                email=email,
                country=country,
                password_hash=generate_password_hash(password, method="pbkdf2:sha256"),
                is_admin=is_admin
            )
            db.session.add(new_user)
            db.session.commit()
            flash("Utilisateur ajouté", "success")
            return redirect(url_for('manage_users'))
    return render_template('add_user.html')

@app.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    current_user = User.query.get(session['user_id'])
    if not current_user.is_admin:
        flash("Vous n'avez pas les droits pour modifier des utilisateurs.", "danger")
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.first_name = request.form['first_name']
        user.last_name = request.form['last_name']
        user.birth_date = datetime.strptime(request.form['birth_date'], '%Y-%m-%d')
        user.email = request.form['email']
        user.country = request.form['country']
        if request.form['password']:
            user.password_hash = generate_password_hash(request.form['password'], method="pbkdf2:sha256")
        user.is_admin = 'is_admin' in request.form
        db.session.commit()
        flash("Utilisateur modifié", "success")
        return redirect(url_for('manage_users'))
    return render_template('edit_user.html', user=user)

@app.route('/users/delete/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    current_user = User.query.get(session['user_id'])
    if not current_user.is_admin:
        flash("Vous n'avez pas les droits pour supprimer des utilisateurs.", "danger")
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash("Utilisateur supprimé", "success")
    return redirect(url_for('manage_users'))

### Gestion des fichiers
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    current_user = User.query.get(session['user_id'])
    if not current_user.is_admin:
        flash("Vous n'avez pas les droits pour uploader des fichiers.", "danger")
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Aucun fichier sélectionné', 'danger')
            return redirect(url_for('upload_file'))
        
        file = request.files['file']
        if file.filename == '':
            flash('Aucun fichier sélectionné', 'danger')
            return redirect(url_for('upload_file'))
            
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            category = auto_assign_category(filename)
            stored_filename, key = encrypt_file(file_path, filename)
            new_file = File(
                original_filename=filename,
                stored_filename=stored_filename,
                category=category,
                encryption_key=key,
                uploaded_by=current_user.id,
                upload_date=datetime.utcnow()
            )
            db.session.add(new_file)
            db.session.commit()
            flash(f"Fichier uploadé et classé en tant que {category}", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Type de fichier non autorisé", "danger")
    return render_template('upload.html')

@app.route('/dashboard', methods=['GET'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    category = request.args.get('category')
    query = request.args.get('q')
    if category:
        files = File.query.filter_by(category=category).all()
    elif query:
        files = File.query.filter(File.original_filename.ilike(f'%{query}%')).all()
    else:
        files = []  # Aucun fichier affiché par défaut jusqu'à sélection d'une catégorie
    return render_template('dashboard.html', files=files)

@app.route('/download/<int:file_id>')
def download_file(file_id):
    # La restriction "3 per hour" a été supprimée
    if 'user_id' not in session:
        return redirect(url_for('login'))
    file_record = File.query.get_or_404(file_id)
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record.stored_filename)
    if os.path.exists(encrypted_path):
        try:
            decrypted_data = decrypt_file(encrypted_path, file_record.encryption_key)
            return send_file(
                io.BytesIO(decrypted_data),
                as_attachment=True,
                download_name=file_record.original_filename,
                mimetype='application/octet-stream'
            )
        except Exception as e:
            flash(f"Erreur lors du décryptage: {str(e)}", "danger")
            return redirect(url_for('dashboard'))
    else:
        flash("Fichier introuvable", "warning")
        return redirect(url_for('dashboard'))

@app.route('/delete_file/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user = User.query.get(session['user_id'])
    if not current_user.is_admin:
        flash("Vous n'avez pas les droits pour supprimer des fichiers.", "danger")
        return redirect(url_for('dashboard'))

    file_record = File.query.get_or_404(file_id)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record.stored_filename)
    
    if os.path.exists(file_path):
        os.remove(file_path)
    
    db.session.delete(file_record)
    db.session.commit()
    
    flash("Fichier supprimé avec succès", "success")
    return redirect(url_for('dashboard'))


### Réinitialisation du mot de passe
@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            return redirect(url_for('verify_security', user_id=user.id))
        else:
            flash("Aucun utilisateur trouvé avec cet email", "danger")
    return render_template('reset_password_request.html')

@app.route('/verify_security/<int:user_id>', methods=['GET', 'POST'])
def verify_security(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        answer = request.form['security_answer']
        if check_password_hash(user.security_answer_hash, answer):
            sms_code = "123456"  # Code statique pour l'exemple
            print(f"Code SMS envoyé à {user.mobile_number} : {sms_code}")
            session['sms_code'] = sms_code
            session['reset_user_id'] = user.id
            return redirect(url_for('verify_sms'))
        else:
            flash("Réponse incorrecte. Veuillez réessayer.", "danger")
    return render_template('verify_security.html', user=user)

@app.route('/verify_sms', methods=['GET', 'POST'])
def verify_sms():
    if request.method == 'POST':
        code_entered = request.form['sms_code']
        if code_entered == session.get('sms_code'):
            user = User.query.get(session.get('reset_user_id'))
            from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
            s = Serializer(app.config['SECRET_KEY'], expires_in=3600)
            token = s.dumps({'user_id': user.id}).decode('utf-8')
            flash("Le code est validé. Vous pouvez maintenant réinitialiser votre mot de passe.", "success")
            return redirect(url_for('reset_password', token=token))
        else:
            flash("Code SMS incorrect. Veuillez réessayer.", "danger")
    return render_template('verify_sms.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
    s = Serializer(app.config['SECRET_KEY'])
    try:
        user_id = s.loads(token)['user_id']
    except Exception:
        flash("Le lien de réinitialisation a expiré", "danger")
        return redirect(url_for('login'))
    user = User.query.get(user_id)
    if request.method == 'POST':
        password = request.form['password']
        user.password_hash = generate_password_hash(password, method="pbkdf2:sha256")
        db.session.commit()
        flash("Votre mot de passe a été réinitialisé", "success")
        return redirect(url_for('login'))
    return render_template('reset_password.html')

if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc')
