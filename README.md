# Gerenciador de Senhas com PyQt6

## Descrição
Este é um projeto de gerenciador de senhas simples implementado em Python usando PyQt6.

## Pré-requisitos
Certifique-se de ter os seguintes requisitos instalados antes de executar o código:

- [Python 3.x](https://www.python.org/downloads/)
- [PyQt6](https://pypi.org/project/PyQt6/)

## Login Screen
First, we have appears the first screen where user need add the correct password to singin into app. We compare the hash of this input with the hash of correct password to determine if user is owner or not. We are using sha256 encrypt algoritmh and hashlib libary from python.

<p align="center">
    <img src="./images/siginscreen.png" alt="Descrição da imagem">
</p>



