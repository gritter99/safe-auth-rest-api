# Trabalho Prático 01: REST API com Autenticação Segura e Criptografia

**Disciplina:** Tópicos Avançados em Segurança Computacional - 2025/1
**Professora:** Lorena Borges
**Aluno(a):** Gabriel Ritter Domingues dos Santos

## 1. Objetivo do Projeto

Desenvolver uma aplicação cliente-servidor que realize comunicação segura entre aplicações através de autenticação segura, via padrão REST e tokens JWT (JSON Web Token) assinados digitalmente. O projeto explora o uso dos algoritmos criptográficos e de autenticação HMAC (HS256) e RSA (RS256 com PKCS#1 v1.5).

## 2. Estrutura do Repositório

O projeto está organizado em duas pastas principais, cada uma representando um cenário de assinatura/verificação de JWT:

* `/rsa`: Contém a implementação utilizando RSA para assinar e verificar JWTs (Cenário 2).
* `/hmac`: Contém a implementação utilizando HMAC para assinar e verificar JWTs (Cenário 1).

Cada uma dessas pastas contém subpastas:
* `/client`: Contém o script do cliente (`client.py`).
* `/server`: Contém os scripts dos servidores (`auth-api.py`, `protected-api.py`) e, no caso do RSA, o script de geração de chaves e os arquivos de chave.

## 3. Pré-requisitos

* Python 3.9 ou superior.
* `pip` (gerenciador de pacotes Python).
* As bibliotecas Python listadas no arquivo `requirements.txt`.

## 4. Configuração do Ambiente

1.  **Clone o Repositório:**
    ```bash
    git clone https://github.com/gritter99/safe-auth-rest-api
    ```

2.  **Crie e Ative um Ambiente Virtual (Recomendado):**
    ```bash
    python -m venv venv
    # No Windows:
    # venv\Scripts\activate
    # No macOS/Linux:
    # source venv/bin/activate
    ```

3.  **Instale as Dependências:**
    Certifique-se de ter um arquivo `requirements.txt` na raiz do seu projeto com o seguinte conteúdo (ou gere-o com `pip freeze > requirements.txt` no seu ambiente virtual após instalar as bibliotecas):
    ```
    PyJWT
    cryptography
    requests
    bcrypt
    ```
    Em seguida, instale as dependências:
    ```bash
    pip install -r requirements.txt
    ```

## 5. Executando o Cenário 2: RSA (RS256)

Esta seção descreve como executar a implementação com JWTs assinados usando RSA.

1.  **Navegue até a Pasta do Servidor RSA:**
    ```bash
    cd rsa/server
    ```

2.  **Gere as Chaves RSA (se ainda não existirem):**
    Este passo é necessário apenas na primeira vez ou se as chaves forem excluídas.
    ```bash
    python generate_keys.py
    ```
    Isso criará os arquivos `rsa_private_key.pem` e `rsa_public_key.pem`.

3.  **Verifique/Popule `USERS_DB` (Opcional):**
    No arquivo `api_autenticacao.py`, existe um dicionário `USERS_DB` com hashes de senha de exemplo. Para testar com usuários específicos, você pode gerar novos hashes de senha usando a função `generate_password_hash` (instruções comentadas no código) e atualizar o dicionário.

4.  **Inicie a API de Autenticação (RSA):**
    Abra um terminal na pasta `rsa/server/` e execute:
    ```bash
    python api_autenticacao.py
    ```
    O servidor de autenticação estará rodando em `http://localhost:8000`.

5.  **Inicie a API Protegida (RSA):**
    Abra **outro terminal** na pasta `rsa/server/` e execute:
    ```bash
    python api_protegida.py
    ```
    O servidor de dados protegidos estará rodando em `http://localhost:8001`.

6.  **Execute o Cliente (RSA):**
    Abra **um terceiro terminal** e navegue até a pasta do cliente RSA:
    ```bash
    cd rsa/client
    ```
    Execute o cliente:
    ```bash
    python client.py
    ```
    Siga as instruções no menu do cliente:
    * **Opção 1:** Faça login (ex: `usuario1` / `senha1`, que foram as criadas por mim, ou as credenciais que você configurou).
    * **Opção 2:** Acesse os dados protegidos.

## 6. Executando o Cenário 1: HMAC (HS256)

Esta seção descreve como executar a implementação com JWTs assinados usando HMAC de forma análoga ao RSA.

1.  **Navegue até a Pasta do Servidor HMAC:**
    (Certifique-se de que os servidores RSA da seção anterior foram parados para evitar conflito de portas, ou altere as portas nos arquivos HMAC se desejar executá-los simultaneamente).
    ```bash
    cd hmac/server
    ```

2.  **Verifique a `HMAC_SECRET_KEY`:**
    Crie um .env e adicione essa variável que será utilizada pelos 2 arquivos do hmac
    Nos arquivos `api_autenticacao.py` e `api_protegida.py` dentro da pasta `hmac/server/`, certifique-se de que a constante `HMAC_SECRET_KEY` está definida e é a mesma em ambos os arquivos.

3.  **Verifique/Popule `USERS_DB` (Opcional):**
    Similar ao cenário RSA, verifique ou atualize o `USERS_DB` em `hmac/server/api_autenticacao.py`.

4.  **Inicie a API de Autenticação (HMAC):**
    Abra um terminal na pasta `hmac/server/` e execute:
    ```bash
    python api_autenticacao.py
    ```
    O servidor de autenticação (HMAC) estará rodando em `http://localhost:8000`.

5.  **Inicie a API Protegida (HMAC):**
    Abra **outro terminal** na pasta `hmac/server/` e execute:
    ```bash
    python api_protegida.py
    ```
    O servidor de dados protegidos (HMAC) estará rodando em `http://localhost:8001`.

6.  **Execute o Cliente (HMAC):**
    Abra **um terceiro terminal** e navegue até a pasta do cliente HMAC:
    ```bash
    cd hmac/client 
    ```
    Execute o cliente:
    ```bash
    python client.py
    ```
    Siga as instruções no menu do cliente, da mesma forma que no cenário RSA.

## 7. Análise de Segurança e Comunicação

* **Comunicação HTTP:** Para fins de desenvolvimento e análise com ferramentas como o Wireshark, os servidores rodam em HTTP. Isso permite a visualização de credenciais e tokens em trânsito, destacando a necessidade crítica de HTTPS em produção.
* **Armazenamento de Senhas:** As senhas dos usuários são armazenadas no servidor utilizando hashes gerados com bcrypt, persistindo apenas o hash.
* **Tokens JWT:** Os JWTs contêm um tempo de expiração e são validados pela `API_Protegida` para verificar a assinatura e as claims.

## 8. Testes Adicionais

Conforme detalhado no relatório, foram considerados testes para:
* JWTs com assinatura inválida.
* JWTs com payload alterado após a assinatura.
* JWTs expirados.

Estes testes podem ser reproduzidos modificando os tokens (manualmente ou via cliente adaptado) ou ajustando o tempo de expiração do token na `API_Autenticacao`.

## 9. Tecnologias Utilizadas

* Python 3
* `pyjwt` (para manipulação de JWT)
* `cryptography` (para primitivas criptográficas RSA e hash)
* `bcrypt` (para hashing de senhas)
* `requests` (para o cliente HTTP)
* Módulos padrão Python: `http.server`, `json`, `datetime`.