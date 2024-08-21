import os
import json
from flask import Flask, render_template, request, redirect, url_for, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui'  # Troque por uma chave secreta segura

# Configurações para upload de arquivos
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Tipos de arquivos permitidos
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Inicialize o LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Função para verificar se o arquivo é permitido
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Função para carregar os projetos do JSON
def carregar_projetos():
    try:
        with open('projetos.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

# Função para salvar os projetos no JSON
def salvar_projetos(projetos):
    # Substituir as barras invertidas por barras normais em todos os projetos
    for projeto in projetos:
        projeto["imagem"] = projeto["imagem"].replace("\\", "/")
    with open('projetos.json', 'w') as f:
        json.dump(projetos, f, indent=4)
        

# Função para carregar os usuários do JSON
def carregar_usuarios():
    try:
        with open('usuarios.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

# Função para salvar os usuários no JSON
def salvar_usuarios(usuarios):
    with open('usuarios.json', 'w') as f:
        json.dump(usuarios, f, indent=4)

# Classe User
class User(UserMixin):
    def __init__(self, id, username, password_hash, is_admin=False):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.is_admin = is_admin

# Função para carregar o usuário
@login_manager.user_loader
def load_user(user_id):
    usuarios = carregar_usuarios()
    for user in usuarios:
        if user['id'] == user_id:
            return User(user['id'], user['username'], user['password_hash'], user['is_admin'])
    return None

# Página de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        usuarios = carregar_usuarios()
        for user in usuarios:
            if user['username'] == username and check_password_hash(user['password_hash'], password):
                login_user(User(user['id'], user['username'], user['password_hash'], user['is_admin']))
                return redirect(url_for('admin'))
        return 'Usuário ou senha inválidos'
    return render_template('login.html')

# Página de registro
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = generate_password_hash(password)
        usuarios = carregar_usuarios()
        user_id = str(len(usuarios) + 1)
        is_admin = False  # Inicialmente não é administrador, pode ser alterado manualmente depois

        new_user = {
            'id': user_id,
            'username': username,
            'password_hash': password_hash,
            'is_admin': is_admin
        }
        usuarios.append(new_user)
        salvar_usuarios(usuarios)
        return redirect(url_for('login'))
    return render_template('register.html')

# Página de administração
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not current_user.is_admin:
        return 'Acesso negado', 403

    projetos = carregar_projetos()

    if request.method == 'POST':
        if 'delete_project' in request.form:
            projeto_id = int(request.form['delete_project'])
            projetos.pop(projeto_id)
            salvar_projetos(projetos)
            return redirect(url_for('admin'))

        nome = request.form.get('nome')
        descricao = request.form.get('descricao')
        link = request.form.get('link')
        imagem = None

        if 'imagem' in request.files:
            file = request.files['imagem']
            if file and allowed_file(file.filename):
                filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
                file.save(filename)
                imagem = os.path.join('uploads', file.filename)

        novo_projeto = {
            'nome': nome,
            'descricao': descricao,
            'imagem': imagem,
            'link': link
        }
        projetos.append(novo_projeto)
        salvar_projetos(projetos)
        return redirect(url_for('admin'))

    return render_template('admin.html', projetos=projetos)

# Página principal
@app.route('/')
def index():
    projetos = carregar_projetos()
    return render_template('index.html', projetos=projetos)

# Logout
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
