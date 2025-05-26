import requests
import json

API_AUTH_URL = "http://localhost:8000"
API_PROTECTED_URL = "http://localhost:8001"

jwt_token = None

def login():
    """
    Solicita credenciais ao usuário, tenta autenticar na API_Autenticacao
    e armazena o token JWT recebido.
    """
    global jwt_token
    print("\n--- Autenticação ---")
    username = input("Digite o nome de usuário: ")
    password = input("Digite a senha: ")

    credentials = {
        "username": username,
        "password": password
    }

    try:
        response = requests.post(f"{API_AUTH_URL}/auth", json=credentials)
        response.raise_for_status()

        token_data = response.json()
        jwt_token = token_data.get("token")

        if jwt_token:
            print("Login bem-sucedido!")
            print(f"Token JWT recebido: {jwt_token}")
        else:
            print("Erro: Token não recebido do servidor de autenticação.")
            error_detail = token_data.get("error", "Nenhum detalhe de erro fornecido.")
            print(f"Detalhe do erro: {error_detail}")

    except requests.exceptions.HTTPError as http_err:
        print(f"Erro HTTP durante o login: {http_err}")
        try:
            error_response = http_err.response.json()
            print(f"Detalhe do erro do servidor: {error_response.get('error')}")
        except json.JSONDecodeError:
            print(f"Resposta não JSON do servidor: {http_err.response.text}")
    except requests.exceptions.RequestException as req_err:
        print(f"Erro de requisição durante o login: {req_err}")
    except Exception as e:
        print(f"Ocorreu um erro inesperado durante o login: {e}")


def access_protected_data():
    """
    Tenta acessar os dados protegidos da API_Protegida usando o token JWT armazenado.
    """
    global jwt_token
    if not jwt_token:
        print("\nVocê precisa fazer login primeiro para obter um token JWT.")
        return

    print("\n--- Acessando Dados Protegidos ---")
    headers = {
        "Authorization": f"Bearer {jwt_token}"
    }

    try:
        response = requests.get(f"{API_PROTECTED_URL}/dados", headers=headers)
        response.raise_for_status()

        protected_data = response.json()
        print("Dados protegidos recebidos com sucesso:")
        print(json.dumps(protected_data, indent=4, ensure_ascii=False))

    except requests.exceptions.HTTPError as http_err:
        print(f"Erro HTTP ao acessar dados protegidos: {http_err}")
        try:
            error_response = http_err.response.json()
            print(f"Detalhe do erro do servidor: {error_response.get('error')}")
        except json.JSONDecodeError:
            print(f"Resposta não JSON do servidor: {http_err.response.text}")
    except requests.exceptions.RequestException as req_err:
        print(f"Erro de requisição ao acessar dados protegidos: {req_err}")
    except Exception as e:
        print(f"Ocorreu um erro inesperado ao acessar dados protegidos: {e}")


def main_menu():
    """
    Exibe o menu principal e gerencia as ações do usuário.
    """
    while True:
        print("\n--- Menu Principal do Cliente ---")
        print("1. Fazer Login (Obter Token JWT)")
        print("2. Acessar Dados Protegidos")
        print("3. Sair")
        choice = input("Escolha uma opção: ")

        if choice == '1':
            login()
        elif choice == '2':
            access_protected_data()
        elif choice == '3':
            print("Saindo...")
            break
        else:
            print("Opção inválida. Tente novamente.")

if __name__ == "__main__":
    print("Iniciando o Cliente...")
    main_menu()