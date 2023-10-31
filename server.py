import socket
import threading

ip_address = '0.0.0.0' # 0.0.0.0 para escutar em todas as interfaces de rede.
port = 9999

def handleClientConnection(data, addr, filename):
    '''
    Lidar com a conexão do cliente e salvar o arquivo recebido.
    '''
    try:
        with open(filename, 'ab') as file:
            file.write(data)
        print(f"Arquivo {filename} recebido com sucesso de {addr[0]}")
    except Exception as e:
        print(f"Erro ao receber arquivo: {e}")

def server():
    '''
    Criação do servidor para aguardar arquivo.
    Sim, estou usando threads para isso.
    '''
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((ip_address, port))

    print(f"Servidor UDP aguardando arquivo na porta {port}...")

    # loop principal para receber dados (que são divididos em blocos)
    while True:
        data, addr = udp_socket.recvfrom(1024)
        filename = f'arquivo_{addr[0]}.txt'

        # criação de thread para lidar com os dados recebidos
        client_handler = threading.Thread(target=handleClientConnection, args=(data, addr, filename))
        client_handler.start()

if __name__ == "__main__":
    server()
