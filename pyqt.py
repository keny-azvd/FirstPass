import sys
from PyQt6.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QVBoxLayout, QPushButton, QTableWidget, QTableWidgetItem
import sys
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QPushButton,  QHeaderView
from PyQt6.QtCore import Qt


class PasswordForm(QWidget):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        # Widgets
        label_secret = QLabel('Secret:')
        line_edit_secret = QLineEdit(self)

        label_key = QLabel('Key:')
        line_edit_key = QLineEdit(self)

        button_login = QPushButton('Add secret', self)
        button_login.clicked.connect(self.encrypt)

        # Layout
        layout = QVBoxLayout()
        layout.addWidget(label_secret)
        layout.addWidget(line_edit_secret)
        layout.addWidget(label_key)
        layout.addWidget(line_edit_key)
        layout.addWidget(button_login)

        self.setLayout(layout)

        self.setWindowTitle('Formulário de Login')
        self.show()
    
    def encrypt(self): # encriptar dados
        secret = self.findChild(QLineEdit, 'line_edit_secret').text()
        key = self.findChild(QLineEdit, 'line_edit_key').text()

        print(f'Secret: {secret}, Key: {key}')

    def write_data(self):  # escreve dados no txt
        return 




class MainForm(QWidget):
    def __init__(self):
        super().__init__()

        self.init_ui()

    def init_ui(self):
        # Widgets para a nova tela
        self.label_welcome = QLabel('Password Manager!')
        self.query_button = QPushButton('Show Password')
        self.query_button_addpwd = QPushButton('Add new password')

        # Layout da nova tela
        layout = QVBoxLayout()
        layout.addWidget(self.label_welcome)
        layout.addWidget(self.query_button)
        layout.addWidget(self.query_button_addpwd)
        self.table_widget = QTableWidget()

        # Configurar a tabela com 3 linhas e 2 colunas como exemplo
        self.table_widget.setRowCount(3)
        self.table_widget.setColumnCount(2)
        a = '1'
        # Preencher a tabela com dados de exemplo
        secrets , hashs = self.read_content()

        for row in range(len(secrets)):
            for col in range(2):
                if(col < 1):
                    item = QTableWidgetItem(f"{secrets[row]}")
                else:
                    item = QTableWidgetItem(f"{hashs[row]}")
                self.table_widget.setItem(row, col, item)
                item = self.table_widget.item(row, col)
        
        # resize table content
        #header = self.table_widget.horizontalHeader()
        #header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        #header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)

        # Definir o layout principal da nova tela
        self.setLayout(layout)
        layout.addWidget(self.table_widget)
        self.table_widget.setColumnWidth(1, 170)
        self.table_widget.setColumnWidth(0, 170)

        # Conectar o botão de consulta e inserção a uma função
        self.query_button.clicked.connect(self.show_pwd)
        self.query_button_addpwd.clicked.connect(self.add_pwd)

        # Configuração da nova tela
        self.setWindowTitle('RSA Pass')
        self.setGeometry(500, 500, 400, 400)

    def show_pwd(self):
        print('Fazer consultas aqui')
    
    def add_pwd(self):
        self.passwordform = PasswordForm()
        self.passwordform.show()
    
    def read_content(self):
        with open('base.txt') as f:
            lines = f.readlines()
            secret_list = []
            hash_list = []
            for i in range(len(lines)-1):
                secret, hash  = lines[i].split(':')
                secret_list.append(secret)
                hash_list.append(hash)
        f.close()
        return secret_list , hash_list




class MyForm(QWidget):
    def __init__(self):
        super().__init__()

        self.init_ui()

    def init_ui(self):
        # Widgets para o formulário de senha
        self.edit_password = QLineEdit()
        self.submit_button = QPushButton('Enviar')

        # Layout do formulário de senha
        layout = QVBoxLayout()
        layout.addWidget(self.edit_password)
        layout.addWidget(self.submit_button)
        self.edit_password.setEchoMode(QLineEdit.EchoMode.Password)

        # Definir o layout principal da janela
        self.setLayout(layout)

        # Configuração do botão de envio
        self.submit_button.clicked.connect(self.submit_form)

        # Configuração da janela principal
        self.setWindowTitle('RSA Pass')
        self.setGeometry(300, 300, 400, 200)

    def submit_form(self):
        # Exemplo de ação ao clicar no botão de envio
        password = self.edit_password.text()
        self.new_form = MainForm()
        self.new_form.show()
        self.close()
        if password == 'kenner':
            print('Você está dentro')
            # Se a senha estiver correta, instanciar e mostrar a nova tela
            self.new_form = MainForm()
            self.new_form.show()
            self.close()


def main():
    app = QApplication(sys.argv)
    form = MyForm()
    form.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()