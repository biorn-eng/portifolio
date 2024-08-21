from werkzeug.security import generate_password_hash

# Substitua 'sua_senha' pela senha desejada para o administrador
senha = '1504'
hash_senha = generate_password_hash(senha)
print(f'Hash da senha: {hash_senha}')
