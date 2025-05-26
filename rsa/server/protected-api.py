from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# --- Configurações ---
HOSTNAME = "localhost"
SERVER_PORT_PROTECTED = 8001 
RSA_PUBLIC_KEY_PATH = "rsa_public_key.pem"

# Carregar a chave pública RSA
try:
    with open(RSA_PUBLIC_KEY_PATH, "rb") as key_file:
        RSA_PUBLIC_KEY = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    print("🗝 Chave pública RSA carregada com sucesso.")
except FileNotFoundError:
    print(f"ERRO: Arquivo da chave pública RSA '{RSA_PUBLIC_KEY_PATH}' não encontrado.")
    print("Execute generate_keys.py primeiro e certifique-se que o arquivo está no local correto.")
    exit(1)
except Exception as e:
    print(f"Erro ao carregar a chave pública RSA: {e}")
    exit(1)

# --- Exemplo de dados protegidos ---
SECRET_DATA = {
    "info": "Estes são dados ultra secretos!",
    "usuarios_ativos": ["usuario1", "convidado"],
    "nivel_acesso": "confidencial"
}

# --- Handler da API Protegida ---
class ProtectedHandler(BaseHTTPRequestHandler):
    def _send_response(self, status_code, data, content_type='application/json'):
        self.send_response(status_code)
        self.send_header('Content-type', content_type)
        self.end_headers()
        if isinstance(data, str):
            self.wfile.write(data.encode('utf-8'))
        else:
            self.wfile.write(json.dumps(data).encode('utf-8'))

    def _verify_jwt(self, token_str):
        try:
            # decodificar e validar o token JWT
            # PyJWT verifica 'exp', 'nbf', 'iat' e a assinatura automaticamente
            # O 'issuer' (iss) também pode ser validado se você passar o parâmetro 'issuer' para jwt.decode()
            payload = jwt.decode(
                token_str,
                RSA_PUBLIC_KEY,
                algorithms=["RS256"], # Deve corresponder ao algoritmo usado para assinar
                issuer="API_Autenticacao" # verificar se a auth-api emitiu
            )
            print(f"Token JWT validado com sucesso para o usuário: {payload.get('sub')}")
            return payload, None
        except jwt.ExpiredSignatureError:
            print("Erro: Token JWT expirou.")
            return None, "Token expirado"
        except jwt.InvalidIssuerError:
            print("Erro: Emissor (issuer) do JWT inválido.")
            return None, "Emissor do token inválido"
        except jwt.InvalidTokenError as e: # Captura outras exceções genéricas de token inválido
            print(f"Erro: Token JWT inválido - {e}")
            return None, f"Token inválido: {e}"
        except Exception as e:
            print(f"Erro inesperado na verificação do JWT: {e}")
            return None, f"Erro na validação do token: {e}"


    def do_GET(self):
        if self.path == '/dados':
            auth_header = self.headers.get('Authorization')
            if not auth_header:
                self._send_response(401, {'error': 'Header de Autorização ausente'})
                return

            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != 'bearer':
                self._send_response(401, {'error': 'Header de Autorização mal formatado. Use: Bearer <token>'})
                return

            token = parts[1]
            payload, error_message = self._verify_jwt(token) # Modificado para retornar a mensagem de erro

            if payload:
                self._send_response(200, SECRET_DATA)
            else:
                self._send_response(401, {'error': error_message or 'Token inválido ou expirado'})
        
        elif self.path == '/health':
            self._send_response(200, {'message': 'Servidor da API Protegida está no ar!'})
        else:
            self._send_response(404, {'error': 'Endpoint não encontrado'})

# --- Função para iniciar o servidor ---
def run_protected_server(server_class=HTTPServer, handler_class=ProtectedHandler, port=SERVER_PORT_PROTECTED):
    server_address = (HOSTNAME, port)
    httpd = server_class(server_address, handler_class)
    print(f"Servidor da API Protegida rodando em http://{HOSTNAME}:{port}")
    print("Endpoint protegido: GET /dados (requer token JWT no header 'Authorization: Bearer <token>')")
    print("Ctrl+C para parar o servidor.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print("Servidor da API Protegida parado.")

if __name__ == '__main__':
    run_protected_server()