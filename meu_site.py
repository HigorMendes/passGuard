from flask import Flask, render_template,make_response,jsonify, send_from_directory, redirect, url_for, request
from cryptography.fernet import Fernet
import mysql.connector
import os
import hashlib
import random
import string

# criando conexão com o banco de dados 
mydb = mysql.connector.connect(
    host = 'localhost',
    user = 'root',
    password = 'root',
    database = 'system_web',
)

# instânciando a classe Flask do framework Flask
app = Flask(__name__)

# fazendo com que os dicionários em Python serializados para JSON não fiquem em ordem alfabética quando "= False"
app.config['JSON_SORT_KEYS'] = False


#definindo a rota da pagina princial, que irá retornar a renderização do HTML da pagina de login
@app.route('/login')
@app.route('/')
def homepage():
    return render_template("login.html")

#definindo a rota da pagina de cadastro, que irá retornar a renderização do HTML da pagina de cadastro
@app.route('/cadastro')
def cadastro():
    return render_template("cadastro.html")

#definindo a rota da pagina do usuário, que irá retornar a renderização do HTML da pagina do usuário após o login
@app.route('/usuarios/<nome_usuario>')
def usuarios(nome_usuario):
    return render_template('usuarios.html', nome_usuario = nome_usuario)

#defindo rota para URLs receberem o CSS, onde <path:filename> é um parâmetro que captura o nome do arquivo CSS solicitado
@app.route('/css/<path:filename>')
def style(filename):
    return send_from_directory(os.path.join(app.root_path, 'static', 'css'), filename)


@app.route('/cadastro_usu', methods=['POST'])
def criaUsu():
    usu = request.json
    #lista de campos obrigatórios que devem estar presentes no objeto JSON a ser enviado na requisição
    campos = ['usuario', 'senha', 'senha_confirm'] 
    if not all(field in usu and usu[field] for field in campos):
        return make_response(
            jsonify({'mensagem': 'Todos os campos são obrigatórios!'}),
            400
        )

    cursor = mydb.cursor() #abre um cursor para executar consultas SQL no banco de dados
    check_sql = "SELECT usuario FROM usuario WHERE usuario = %s" #consulta SQL para verificar se o usuário já está cadastrado no banco de dados
    cursor.execute(check_sql, (usu['usuario'],))
    usuario_ex = cursor.fetchone()
    
    #verifica se usuário já cadastrado
    if usuario_ex:
        return make_response(
            jsonify({'mensagem': 'Usuário já cadastrado!', 'dados': usu}),
            409  
        )
    #verifica se senha e confirmação são diferentes
    elif usu['senha'] != usu['senha_confirm']:
        return make_response(
            jsonify({'mensagem': 'A senha e a confirmação de senha não coincidem'}),
            400  
        )

    #gera um hash SHA-256 para a senha e confirmação da senha
    senha = hashlib.sha256(usu['senha'].encode()).hexdigest()
    senha_confirm = hashlib.sha256(usu['senha_confirm'].encode()).hexdigest() 
    

    insert_sql = "INSERT INTO usuario (usuario, senha, senha_confirm) VALUES (%s, %s, %s)" #comando sql insert a ser executado criando um usuario
    values = (usu['usuario'], senha, senha_confirm) #definindo os valores com os inputs do usuario, e senhas em hash
    cursor.execute(insert_sql, values) #insere o novo registro no banco de dados
    mydb.commit() #confirma a transação com o banco de dados

    return make_response(
        jsonify({'mensagem': 'Cadastrado com sucesso!', 'dados': usu}),
        201  
    )


@app.route('/login', methods=['POST'])
def login():
    dados_login = request.json

    # Verifica se o usuário e a senha foram fornecidos e se não estão vazios
    if 'usuario' not in dados_login or not dados_login['usuario']:
        return jsonify({'mensagem': 'Usuário é obrigatório'}), 400
    if 'senha' not in dados_login or not dados_login['senha']:
        return jsonify({'mensagem': 'Senha é obrigatória'}), 400

    usuario = dados_login['usuario']
    senha = dados_login['senha']

    # Consulta o banco de dados para verificar se o usuário existe
    cursor = mydb.cursor()
    cursor.execute("SELECT usuario, senha FROM usuario WHERE usuario = %s", (usuario,))
    resultado = cursor.fetchone()

    # Se o usuário não existe, retorna um erro
    if not resultado:
        return jsonify({'mensagem': 'Usuário não cadastrado!'}), 401

    # Verifica se a senha fornecida corresponde ao hash armazenado no banco de dados
    senha_hash_db = resultado[1]  # O hash da senha está no segundo elemento da tupla
    senha_hash_fornecida = hashlib.sha256(senha.encode()).hexdigest()

    if senha_hash_fornecida == senha_hash_db:
        # Redireciona o usuário para a página do usuário logado
        return redirect(url_for('usuarios', nome_usuario=usuario))

    else:
        # Retorna uma mensagem de erro se a senha estiver incorreta
        return jsonify({'mensagem': 'Senha inválida!'}), 401
    

# Chave para criptografia
chave = Fernet.generate_key()
criptografia = Fernet(chave)

@app.route('/salvar_dados', methods=['POST'])
def salvar_dados():
    cursor = mydb.cursor()
    data = request.get_json()

    usuario = data.get('usuario')
    senha_original = data['senha_gerada']
    site = data['site']
    login = data['login']

    # Criptografar os dados
    senha_criptografada = criptografia.encrypt(senha_original.encode())
    login_criptografado = criptografia.encrypt(login.encode())

    # Inserir os dados no banco de dados
    sql = "INSERT INTO passwords (usuario, senha_gerada, site, login) VALUES (%s, %s, %s, %s)"
    val = (usuario, senha_criptografada, site, login_criptografado)
    cursor.execute(sql, val)
    mydb.commit()

    return jsonify({"message": "Dados salvos com sucesso!"}), 200



@app.route('/recuperar_dados/<nome_usuario>', methods=['GET'])
def recuperar_dados(nome_usuario):
    cursor = mydb.cursor(dictionary=True)
    sql = "SELECT * FROM passwords WHERE usuario = %s"
    val = (nome_usuario,)
    cursor.execute(sql, val)
    result = cursor.fetchall()

    if not result:
        return jsonify({"message": "Usuário não tem senhas cadastradas!"}), 404

    # Descriptografar os dados
    for linha in result:
        senha_criptografada = linha['senha_gerada']
        senha_original = criptografia.decrypt(senha_criptografada).decode()

        login_criptografado = linha['login']
        login_original = criptografia.decrypt(login_criptografado).decode()

        linha['senha_gerada'] = senha_original
        linha['login'] = login_original

    return jsonify(result)

def generate_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    # não repetir caracteres especiais
    password = ''.join(random.choices(characters, k=length-1))
    password += random.choice(string.punctuation)
    # Embaralhando a senha
    password_list = list(password)
    random.shuffle(password_list)
    password = ''.join(password_list)
    return password

@app.route('/api/generate_password', methods=['GET'])
def get_password():
    password = generate_password()
    return jsonify({'password': password})

    
if __name__ == '__main__':
    app.run(debug=True)