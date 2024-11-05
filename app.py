from flask import Flask, request, render_template, redirect, url_for, jsonify, session
from flask_pymongo import PyMongo
from dotenv import load_dotenv
import os
from auth import requires_auth, hash_password, init_mongo, verify_password

load_dotenv('.cred')
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "vicco")
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
mongo = PyMongo(app)

# Inicialize o mongo no auth.py
init_mongo(mongo)

# Rota para a página principal
@app.route('/')
def home():
    return render_template('index.html') , 200

# Rota para a página de cadastro
@app.route('/signin')
def signin():
    return render_template('signin.html') , 200

@app.route('/usuarios', methods=['POST'])
def create_user():
    usuario = request.form.get('usuario')
    senha = request.form.get('senha')
    email = request.form.get('email')

    if not usuario or not senha or not email:
        return jsonify({"error": "Nome, usuário, senha e email são obrigatórios"}), 400

    if mongo.db.usuarios.find_one({"usuario": usuario}):
        return jsonify({"error": "Usuário já existe"}), 409

    if mongo.db.usuarios.find_one({"email": email}):
        return jsonify({"error": "E-mail já cadastrado"}), 409

    hashed_password = hash_password(senha)
    user_data = {"usuario": usuario, "senha": hashed_password, "email": email}
    mongo.db.usuarios.insert_one(user_data)

    return redirect(url_for('success')), 302

# Rota de sucesso
@app.route('/success')
def success():
    return render_template('sucesso.html'), 200 

# Rota para a página de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')  # Mudamos de 'usuario' para 'email'
        senha = request.form.get('senha')
        user = mongo.db.usuarios.find_one({"email": email})  # Buscar pelo e-mail
        if user and verify_password(user['senha'], senha):
            session['user'] = user['usuario']  # Armazena o usuário na sessão
            return redirect(url_for('profile')), 302
        return jsonify({"error": "E-mail ou senha incorretos"}), 401

    return render_template('login.html'), 200


@app.route('/logout')
def logout():
    session.pop('username', None)  # Remove 'username' da sessão
    session.pop('user', None)       # Remove 'user' da sessão
    return redirect(url_for('home')) , 302


# Rota para a página de perfil
@app.route('/profile')
def profile():
    # Verifica se o usuário está autenticado
    if 'user' not in session:
        return redirect(url_for('login')), 302

    return render_template('home_login.html', user=session.get('user')), 200

if __name__ == '__main__':
    app.run(debug=True)
