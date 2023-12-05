import sys
from PyQt6.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QVBoxLayout, QPushButton, QTableWidget, QTableWidgetItem
import sys
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QPushButton,  QHeaderView ,QMainWindow
from PyQt6.QtCore import Qt
from cryptography.hazmat.primitives.asymmetric import rsa , padding
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import hashlib


class SenhaViewer(QMainWindow):
    def __init__(self, senha):
        super().__init__()

        central_widget = QWidget(self)
        layout = QVBoxLayout(central_widget)

        # Adicione um QLabel ou outro widget para exibir a senha
        self.label_senha = QLabel(f"Senha: {senha}", self)

        # Adicione um botão para fechar a janela
        btn_fechar = QPushButton("Fechar", self)
        btn_fechar.clicked.connect(self.close)

        layout.addWidget(self.label_senha)
        layout.addWidget(btn_fechar)

        self.setCentralWidget(central_widget)
        self.setWindowTitle("Visualizador de Senha")

class PasswordForm(QWidget):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        # Widgets
        self.label_secret = QLabel('Secret:')
        self.line_edit_secret = QLineEdit(self)

        self.label_password = QLabel('Password:')
        self.line_edit_password = QLineEdit(self)
        self.line_edit_password.setEchoMode(QLineEdit.EchoMode.Password)

        button_login = QPushButton('Add secret', self)
        button_login.clicked.connect(self.encrypt)

        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.label_secret)
        layout.addWidget(self.line_edit_secret)
        layout.addWidget(self.label_password)
        layout.addWidget(self.line_edit_password)
        layout.addWidget(button_login)

        self.setLayout(layout)
        

        self.setWindowTitle('Formulário de Login')
        self.show()
    
    def encrypt(self): 
        # get variables
        secret = self.line_edit_secret.text()
        password = self.line_edit_password.text()
        message = bytes(password,encoding="utf-8") # convert to bytes
        
        #generate private encrypt and storage
        private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.BestAvailableEncryption(b'kenner'))
        f = open(f"./private_keys/{secret}.bin", "wb")
        f.write(pem)
        f.close()
        public_key = private_key.public_key()

        # encrypt data and storage cypher text
        ciphertext = public_key.encrypt(message,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None))
        self.write_data(secret,ciphertext)

    def write_data(self, secret, ciphertext):  
        f = open(f"./secrets/{secret}.bin", "wb")
        f.write(ciphertext)
        f.close()
        self.close()  # close the current window
        self.reload = MainForm() 
        self.reload.show() # reload main form
        return None 




class MainForm(QWidget):
    def __init__(self):
        super().__init__()

        self.init_ui()

    def init_ui(self):
        # Widgets para a nova tela
        self.label_welcome = QLabel('Password Manager!')
        self.query_button_addpwd = QPushButton('Add new password')

        # Layout da nova tela
        layout = QVBoxLayout()
        layout.addWidget(self.label_welcome)
        layout.addWidget(self.query_button_addpwd)
        self.table_widget = QTableWidget()
        
        self.write_table()

        # Definir o layout principal da nova tela
        self.setLayout(layout)
        layout.addWidget(self.table_widget)
        self.table_widget.setColumnWidth(1, 170)
        self.table_widget.setColumnWidth(0, 170)

        # Conectar o botão de consulta e inserção a uma função
        self.query_button_addpwd.clicked.connect(self.add_pwd)
        self.table_widget.cellClicked.connect(self.cell_clicked)
        self.table_widget.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)


        # Configuração da nova tela
        self.setWindowTitle('RSA Pass')
        self.setGeometry(500, 500, 400, 400)

    def write_table(self):
        secrets , hashs = self.read_content()
        # Configurar a tabela com 3 linhas e 2 colunas como exemplo
        self.table_widget.setRowCount(len(secrets))
        self.table_widget.setColumnCount(2)

        for row in range(len(secrets)):
            for col in range(2):
                if(col < 1):
                    item = QTableWidgetItem(f"{secrets[row]}")
                else:
                    item = QTableWidgetItem(" .... ")
                self.table_widget.setItem(row, col, item)
                item = self.table_widget.item(row, col)    

    def add_pwd(self):
        self.passwordform = PasswordForm()
        self.passwordform.show()
        self.close()
    
    def read_content(self):
        dir_path = './secrets/'
        secrets_list = []
        for path in os.listdir(dir_path):
            secrets_list.append(path.split('.')[0])
        return secrets_list , None
    
    def cell_clicked(self, row, col):
        item = self.table_widget.item(row, col)
        if item:
            value = item.text()
            f = open(f"./secrets/{value}.bin", "rb")
            private_key = open(f"./private_keys/{value}.bin", "rb")
            
            pem = private_key.read()
            data_encrypted = f.read()

            password = b'kenner'

            # Carregue a chave privada usando o PEM e a senha
            key = serialization.load_pem_private_key(
                pem,
                password=password,
                backend=default_backend()
            )

            plaintext = key.decrypt(
                        data_encrypted,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )

            #print(plaintext.decode('utf-8'))

                  # Crie uma instância da nova classe SenhaViewer
            self.viewer = SenhaViewer(plaintext.decode('utf-8'))
            self.viewer.show()

                                    
            

class MyForm(QWidget):
    def __init__(self):
        super().__init__()

        self.init_ui()

    def init_ui(self):
        # Widgets para o formulário de senha
        self.edit_password = QLineEdit()
        self.submit_button = QPushButton('Enviar')

        # Layout do formulário de senha
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.edit_password)
        self.layout.addWidget(self.submit_button)
        self.edit_password.setEchoMode(QLineEdit.EchoMode.Password)

        # Definir o layout principal da janela
        self.setLayout(self.layout)

        # Configuração do botão de envio
        self.submit_button.clicked.connect(self.submit_form)


        # Configuração da janela principal
        self.setWindowTitle('RSA Pass')
        self.setGeometry(800, 800, 400, 200)
        
        

    def submit_form(self):
        # create hash of password input
        password = self.edit_password.text()
        password_hash = self.hash_password(password)
        # get hash of correct password
        master_data = open(f"./master.txt", "r")
        master_hash = master_data.read()
        if(password_hash == master_hash.strip()):
            print('Você está dentro')
            # if password is correct, will allow go to main form
            self.new_form = MainForm()
            self.new_form.show()
            self.close()

    

    def hash_password(self,password):
        password_bytes = password.encode('utf-8')
        hash_object = hashlib.sha256(password_bytes)
        
        return hash_object.hexdigest()


def main():
    app = QApplication(sys.argv)
    form = MyForm()
    form.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()