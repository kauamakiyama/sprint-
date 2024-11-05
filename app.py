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

init_mongo(mongo)


@app.route('/')
def home():
    return render_template('index.html') , 200


@app.route('/signin')
def signin():
    return render_template('signin.html') , 200

@app.route('/usuarios', methods=['POST'])
def create_user():
    usuario = request.form.get('usuario')
    senha = request.form.get('senha')
    email = request.form.get('email')

    if not usuario or not senha or not email:
        return render_template('signin.html', error="Nome, usuário, senha e email são obrigatórios"), 400

    if mongo.db.usuarios.find_one({"usuario": usuario}):
        return render_template('signin.html', error="Usuário já está sendo usado"), 409

    if mongo.db.usuarios.find_one({"email": email}):
        return render_template('signin.html', error="E-mail já cadastrado"), 409

    hashed_password = hash_password(senha)
    user_data = {"usuario": usuario, "senha": hashed_password, "email": email}
    mongo.db.usuarios.insert_one(user_data)

    return redirect(url_for('success')), 302

@app.route('/success')
def success():
    return render_template('sucesso.html'), 200 


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')  
        senha = request.form.get('senha')
        user = mongo.db.usuarios.find_one({"email": email})  
        if user and verify_password(user['senha'], senha):
            session['user'] = user['usuario']  
            return redirect(url_for('profile')), 302
        
        error = "E-mail ou senha incorretos"

    return render_template('login.html', error=error), 200


@app.route('/logout')
def logout():
    session.pop('username', None)  
    session.pop('user', None)       
    return redirect(url_for('home')) , 302



@app.route('/profile')
def profile():
    
    if 'user' not in session:
        return redirect(url_for('login')), 302

    return render_template('home_login.html', user=session.get('user')), 200

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = mongo.db.usuarios.find_one({"email": email})

        if user:
            return redirect(url_for('reset_password', email=email))
        else:
            error_message = "E-mail não encontrado. Verifique seu e-mail ou cadastre-se."
            return render_template('forgot_password.html', error_message=error_message)

    return render_template('forgot_password.html')


@app.route('/confirm_email', methods=['POST'])
def confirm_email():
    email = request.form.get('email')


    print(f"E-mail recebido na confirmação: {email}")

    user = mongo.db.usuarios.find_one({"email": email})

    if user:

        return redirect(url_for('reset_password', email=email))
    else:
        return jsonify({"error": "E-mail não encontrado"}), 404


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':

        email = request.form.get('email')
        print(f"Email recebido na redefinição de senha (POST): {email}")

        nova_senha = request.form.get('nova_senha')
        confirmar_senha = request.form.get('confirmar_senha')

        if nova_senha != confirmar_senha:
            error_message = "As senhas não coincidem."
            return render_template('reset_password.html', email=email, error_message=error_message)

        nova_senha_hash = hash_password(nova_senha)


        result = mongo.db.usuarios.update_one(
            {"email": email}, 
            {"$set": {"senha": nova_senha_hash}}
        )

        if result.modified_count == 1:
            return redirect(url_for('success_senha'))
        else:
            error_message = "Não foi possível atualizar a senha."
            return render_template('reset_password.html', email=email, error_message=error_message)

    email = request.args.get('email')
    print(f"Email recebido no GET: {email}")


    return render_template('reset_password.html', email=email)





@app.route('/success_senha')
def success_senha():
    return render_template('sucesso_senha.html')


if __name__ == '__main__':
    app.run(debug=True)
