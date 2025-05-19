import hashlib
import requests
import os
import csv
import re
from getpass import getpass

def gerar_hash_sha1(senha):
    return hashlib.sha1(senha.encode('utf-8')).hexdigest().upper()

def consultar_api(prefixo):
    url = f'https://api.pwnedpasswords.com/range/{prefixo}'
    resposta = requests.get(url)
    if resposta.status_code != 200:
        raise RuntimeError(f'Erro na API: {resposta.status_code}')
    return resposta.text

def verificar_senha_vazada(senha):
    hash_completo = gerar_hash_sha1(senha)
    prefixo, sufixo = hash_completo[:5], hash_completo[5:]
    resposta_api = consultar_api(prefixo)

    for linha in resposta_api.splitlines():
        hash_sufixo, qtd = linha.split(':')
        if hash_sufixo == sufixo:
            return int(qtd)
    return 0

def verificar_forca_senha(senha):
    if len(senha) < 8:
        return "Fraca"
    if not re.search(r'\d', senha):
        return "Moderada"
    if not re.search(r'[A-Z]', senha):
        return "Moderada"
    if not re.search(r'[@#$%^&+=]', senha):
        return "Moderada"
    return "Forte"

def verificar_arquivo(caminho):
    if not os.path.isfile(caminho):
        print("❌ Arquivo não encontrado.")
        return

    with open(caminho, 'r', encoding='utf-8') as f:
        senhas = [linha.strip() for linha in f if linha.strip()]

    print(f"\n🔍 Verificando {len(senhas)} senha(s)...\n")
    resultados = []

    for senha in senhas:
        try:
            resultado = verificar_senha_vazada(senha)
            forca = verificar_forca_senha(senha)
            resultados.append((senha, resultado, forca))

            if resultado:
                print(f"⚠️ '{senha}' foi vazada {resultado} vez(es). Força: {forca}.")
            else:
                print(f"✅ '{senha}' não foi encontrada em vazamentos. Força: {forca}.")
        except Exception as e:
            print(f"Erro ao verificar '{senha}': {e}")

    # Exportar para CSV
    with open('relatorio.csv', 'w', newline='', encoding='utf-8') as csvfile:
        escritor = csv.writer(csvfile)
        escritor.writerow(['Senha', 'Vazamentos encontrados', 'Força da Senha'])

        for senha, qtd, forca in resultados:
            escritor.writerow([senha, qtd, forca])

    print("\n📁 Relatório salvo como 'relatorio.csv'.")

if __name__ == '__main__':
    print("=== Verificador de Senhas Vazadas ===\n")
    modo = input("Verificar senha única (1) ou arquivo de senhas (2)? ")

    if modo == '1':
        senha = getpass("Digite a senha (ela não será exibida): ")
        resultado = verificar_senha_vazada(senha)
        forca = verificar_forca_senha(senha)
        if resultado:
            print(f"\n⚠️ Sua senha foi encontrada {resultado} vezes em vazamentos. Força: {forca}.")
        else:
            print(f"\n✅ Sua senha não foi encontrada em vazamentos. Força: {forca}.")
    elif modo == '2':
        caminho = input("Digite o caminho do arquivo de senhas (.txt): ")
        verificar_arquivo(caminho)
    else:
        print("Opção inválida.")
