from flask import Flask, request, render_template, redirect, url_for,jsonify
from flask_pymongo import PyMongo
from dotenv import load_dotenv
import os
from auth import requires_auth, hash_password, init_mongo

load_dotenv('.cred')
app = Flask(__name__)
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
mongo = PyMongo(app)

# Inicialize o mongo no auth.py
init_mongo(mongo)

# Rota para a página principal
@app.route('/')
def home():
    return render_template('index.html')

# Rota para a página de cadastro
@app.route('/signin')
def signin():
    return render_template('signin.html')

# Rota para criar um novo usuário
@app.route('/usuarios', methods=['POST'])
def create_user():
    nome = request.form.get('nome')
    usuario = request.form.get('usuario')
    senha = request.form.get('senha')

    if not nome or not usuario or not senha:
        return jsonify({"error": "Nome, usuário e senha são obrigatórios"}), 400

    if mongo.db.usuarios.find_one({"usuario": usuario}):
        return jsonify({"error": "Usuário já existe"}), 409

    hashed_password = hash_password(senha)
    user_data = {"nome": nome, "usuario": usuario, "senha": hashed_password}
    mongo.db.usuarios.insert_one(user_data)

    return redirect(url_for('success'))

# Rota de sucesso
@app.route('/success')
def success():
    return render_template('sucesso.html')

if __name__ == '__main__':
    app.run(debug=True)
