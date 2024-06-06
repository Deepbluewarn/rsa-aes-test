import sys
import os
import random
import string
import base64
from PyQt5.QtWidgets import *
from rsa_ui import Ui_Dialog

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

private_key_filename = f'private_key.pem'
public_key_filename = f'public_key.pem'

class RSA_Dialog(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.setupSlots()

        if (not os.path.exists('private_key.pem')) or (not os.path.exists('public_key.pem')):
            self.genNewKey()
        else:
            self.setKeyInfo()
        self.show()
    
    def setupSlots(self):
        # 평문 텍스트 파일 불러오기 버튼
        getDecFile = self.ui.pushButton_Get_DecryptedFile
        getDecFile.clicked.connect(self.showDialogForDec)

        # 암호문 텍스트 파일 불러오기 버튼=
        getEncFile = self.ui.pushButton_Get_EncryptedFile
        getEncFile.clicked.connect(self.showDialogForEnc)

        # 새로운 키 쌍 생성 버튼
        genNewKey = self.ui.pushButton_new_key
        genNewKey.clicked.connect(self.genNewKey)

        # 평문을 텍스트 파일로 저장
        saveDecToFile = self.ui.pushButton_Save_DecryptedFile
        saveDecToFile.clicked.connect(self.saveDecryptedToFile)

        # 암호문을 텍스트 파일로 저장
        saveEncToFile = self.ui.pushButton_Save_EncryptedFile
        saveEncToFile.clicked.connect(self.saveEncryptedToFile)

        # Encrypt!
        EncryptBtn = self.ui.pushButton_Encrypt
        EncryptBtn.clicked.connect(self.encryptText)

        # Decrypt!
        DecryptBtn = self.ui.pushButton_Decrypt
        DecryptBtn.clicked.connect(self.decryptText)

    def encryptText(self):
        try: 
            decTextInput = self.ui.plainTextEdit_Decrypted
            data_to_encrypt = decTextInput.toPlainText().encode('utf-8')
            
            # AES 대칭 키 생성
            aes_key = get_random_bytes(16)
            cipher_aes = AES.new(aes_key, AES.MODE_EAX)
            nonce = cipher_aes.nonce
            ciphertext, tag = cipher_aes.encrypt_and_digest(data_to_encrypt)

            # AES 키를 RSA로 암호화
            public_key = self.load_key_from_pem(public_key_filename)
            cipher_rsa = self.create_cipher_with_key(public_key)
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)

            # 암호화된 AES 키와 nonce 및 암호문을 결합
            encrypted_data = base64.b64encode(encrypted_aes_key + nonce + ciphertext).decode('utf-8')

            encTextEdit = self.ui.plainTextEdit_Encrypted
            encTextEdit.setPlainText(encrypted_data)
        except Exception as e:
            self.ui.label_error_msg.setText(str(e))

    def decryptText(self):
        try:
            encTextInput = self.ui.plainTextEdit_Encrypted
            encoded_data_to_decrypt = encTextInput.toPlainText().encode('utf-8')
            encrypted_data = base64.b64decode(encoded_data_to_decrypt)

            # 암호화된 AES 키, nonce, 암호문 분리
            private_key = self.load_key_from_pem(private_key_filename)
            encrypted_aes_key_size = private_key.size_in_bytes()
            encrypted_aes_key = encrypted_data[:encrypted_aes_key_size]
            nonce = encrypted_data[encrypted_aes_key_size:encrypted_aes_key_size + 16]
            ciphertext = encrypted_data[encrypted_aes_key_size + 16:]

            # RSA로 AES 키 복호화
            cipher_rsa = PKCS1_OAEP.new(private_key)
            aes_key = cipher_rsa.decrypt(encrypted_aes_key)

            # AES로 데이터 복호화
            cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            decrypted = cipher_aes.decrypt(ciphertext)

            decTextEdit = self.ui.plainTextEdit_Decrypted
            decTextEdit.setPlainText(decrypted.decode('utf-8'))
        except Exception as e:
            self.ui.label_error_msg.setText(str(e))
    
    def saveDecryptedToFile(self):
        text = self.ui.plainTextEdit_Decrypted.toPlainText()
        # 파일 저장 대화상자 열기
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_name, _ = QFileDialog.getSaveFileName(self, "평문을 텍스트로 저장", "", "Text Files (*.txt);;All Files (*)", options=options)
        if file_name:
            with open(f'{file_name}.txt', "w", encoding="utf-8") as file:
                file.write(text)

    def saveEncryptedToFile(self):
        text = self.ui.plainTextEdit_Encrypted.toPlainText()
        # 파일 저장 대화상자 열기
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_name, _ = QFileDialog.getSaveFileName(self, "암호문을 텍스트로 저장", "", "Text Files (*.txt);;All Files (*)", options=options)
        if file_name:
            with open(f'{file_name}.txt', "w", encoding="utf-8") as file:
                file.write(text)

    def showDialogForDec(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_path, _ = QFileDialog.getOpenFileName(self, "평문 텍스트 파일 가져오기", "", "Text Files (*.txt);;All Files (*)", options=options)
        
        if file_path:
            with open(file_path, 'r', encoding='utf-8') as file:
                file_contents = file.read()
                self.ui.plainTextEdit_Decrypted.setPlainText(file_contents)
    
    def showDialogForEnc(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_path, _ = QFileDialog.getOpenFileName(self, "암호문 텍스트 파일 가져오기", "", "Text Files (*.txt);;All Files (*)", options=options)
        
        if file_path:
            with open(file_path, 'r', encoding='utf-8') as file:
                file_contents = file.read()
                self.ui.plainTextEdit_Encrypted.setPlainText(file_contents)
    
    def genNewKey(self):
        global private_key_filename, public_key_filename
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        private_key_path = os.path.abspath(private_key_filename)
        public_key_path = os.path.abspath(public_key_filename)
        
        with open(private_key_filename, "wb") as priv_file:
            priv_file.write(private_key)

        with open(public_key_filename, "wb") as pub_file:
            pub_file.write(public_key)

        self.ui.textEdit_public_key.setText(public_key_path)
        self.ui.textEdit_private_key.setText(private_key_path)
        
        print("키 생성 및 저장이 완료되었습니다.")

    def setKeyInfo(self):
        global private_key_filename, public_key_filename

        self.ui.textEdit_public_key.setText(os.path.abspath(private_key_filename))
        self.ui.textEdit_private_key.setText(os.path.abspath(public_key_filename))

    def load_key_from_pem(self, pem_file_path):
    # PEM 파일에서 공개 키 읽기
        with open(pem_file_path, 'rb') as pem_file:
            key = RSA.import_key(pem_file.read())
        return key

    def create_cipher_with_key(self, key):
        # 공개 키로 PKCS1_OAEP 객체 생성
        cipher = PKCS1_OAEP.new(key)
        return cipher

if __name__ == '__main__':
    app = QApplication(sys.argv)
    appwindow = RSA_Dialog()
    appwindow.show()
    sys.exit(app.exec_())
