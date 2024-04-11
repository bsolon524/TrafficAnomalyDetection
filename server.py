import socket
import numpy as np
from joblib import load

def start_server(host='127.0.0.1', port=65432):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.bind((host, port))
            print(f"Server listening on {host}:{port}")
            while True:
                data, addr = s.recvfrom(1024)
                print(f"Received from {addr}: {data.decode()}")
        except KeyboardInterrupt:
            print("Stopped receiving packets")

if __name__ == "__main__":
    start_server()
