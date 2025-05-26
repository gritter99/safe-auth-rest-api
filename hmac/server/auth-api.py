from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import jwt
import datetime
import bcrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv
import os

load_dotenv()
HMAC_SECRET_KEY = os.getenv("HMAC_SECRET_KEY")

# --- Configurações e Dados Mock (Simulados) ---
HOSTNAME = "localhost"
SERVER_PORT_AUTH = 8000

def generate_password_hash(password_text):
    """
    Gera um hash bcrypt para uma senha em texto.
    """
    password_bytes = password_text.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    return hashed_password.decode('utf-8')


USERS_DB = {
    "usuario1": '$2b$12$2HnRe86Cj8JDm0jAHilpjO5Y4Zld/Omy7jYF3vveMCJd7rFSC3/EG', # Exemplo: hash de "senha1"
}


# --- Handler da API de Autenticação ---
class AuthHandler(BaseHTTPRequestHandler):
    def _send_response(self, status_code, data):
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def do_POST(self):
        if self.path == '/auth':
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                credentials = json.loads(post_data.decode('utf-8'))

                username = credentials.get('username')
                password = credentials.get('password')

                if not username or not password:
                    self._send_response(400, {'error': 'Usuário e senha são obrigatórios'})
                    return

                hashed_password_from_db = USERS_DB.get(username)
                if hashed_password_from_db and \
                   bcrypt.checkpw(password.encode('utf-8'), hashed_password_from_db.encode('utf-8')):
                    
                    payload = {
                        'sub': username, # Subject (identificador do usuário)
                        'iat': datetime.datetime.now(datetime.timezone.utc), # Issued at (quando foi emitido)
                        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=1), # Expiration time
                        'iss': 'API_Autenticacao' # Issuer (emissor do token)
                    }
                    

                    signed_jwt = jwt.encode(payload, HMAC_SECRET_KEY, algorithm="HS256")
                    
                    print(f"Usuário '{username}' autenticado. JWT gerado.")
                    self._send_response(200, {'token': signed_jwt})
                else:
                    print(f"Falha na autenticação para o usuário '{username}'.")
                    self._send_response(401, {'error': 'Credenciais inválidas'})

            except json.JSONDecodeError:
                self._send_response(400, {'error': 'JSON mal formatado'})
            except Exception as e:
                print(f"Erro interno no servidor: {e}")
                self._send_response(500, {'error': f'Erro interno do servidor: {str(e)}'})
        else:
            self._send_response(404, {'error': 'Endpoint não encontrado'})

    def do_GET(self): 
        if self.path == '/health':
            self._send_response(200, {'message': 'Servidor de Autenticação está no ar!'})
        else:
            self._send_response(404, {'error': 'Endpoint não encontrado'})


def run_auth_server(server_class=HTTPServer, handler_class=AuthHandler, port=SERVER_PORT_AUTH):
    server_address = (HOSTNAME, port)
    httpd = server_class(server_address, handler_class)
    print(f"Servidor de Autenticação (API_Autenticacao) rodando em http://{HOSTNAME}:{port}")
    print("Endpoint de autenticação: POST /auth")
    print("Ctrl+C para parar o servidor.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print("Servidor de Autenticação parado.")

if __name__ == '__main__':    
    # --- SEÇÃO PARA GERAR HASHES (PARA DESENVOLVIMENTO) ---
    # print("--- Gerador de Hashes de Teste ---")
    # senha_para_usuario1 = "senha1"
    # hash_real_para_usuario1 = generate_password_hash(senha_para_usuario1)
    # print(f"Para o usuário 'usuario1' com senha '{senha_para_usuario1}', o hash real é:")
    # print(f"'{hash_real_para_usuario1}'")
    # print("-----------------------------------")
    run_auth_server()