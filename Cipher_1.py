# -*- coding: utf-8 -*-

import os
import random

from PyQt5 import QtCore
from PyQt5 import QtWidgets
from PyQt5 import QtGui

import hashlib

import BC1_LUT as BC1
import AES
import TabWidgets


def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


class MainWidget(QtWidgets.QWidget):
    def __init__(self, parent=None):
        QtWidgets.QWidget.__init__(self, parent)

        self.block_cipher = BC1.BlockCipher()
        self.aes_cipher = AES.BlockCipher()
        self.block_cipher.signal.connect(self.ch_value)
        self.aes_cipher.signal.connect(self.ch_value)

        exit_action = QtWidgets.QAction(QtGui.QIcon(resource_path('exit.png')), '&Выйти', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.setStatusTip('Закрыть приложение')
        exit_action.triggered.connect(QtWidgets.qApp.quit)

        open_file = QtWidgets.QAction(QtGui.QIcon(resource_path('open.png')), '&Открыть', self)
        open_file.setShortcut('Ctrl+O')
        open_file.setStatusTip('Открыть файл')
        open_file.triggered.connect(self.show_dialog_open)

        save_action = QtWidgets.QAction(QtGui.QIcon(resource_path('save.png')), '&Сохранить', self)
        save_action.setShortcut('Ctrl+S')
        save_action.setStatusTip('Сохранить файл')
        save_action.triggered.connect(self.export)

        open_settings_action = QtWidgets.QAction(QtGui.QIcon(), 'Параметры', self)
        open_settings_action.setShortcut('Ctrl+S')
        open_settings_action.setStatusTip('Настройки параметров режимов шифрования')
        open_settings_action.triggered.connect(self.open_settings)

        clear_action = QtWidgets.QAction(QtGui.QIcon(resource_path('minus.png')), '&Очистить', self)
        clear_action.triggered.connect(self.clear)

        gen_action = QtWidgets.QAction(QtGui.QIcon(resource_path('b_primary.png')), 'Получить ключ', self)
        gen_action.setShortcut('Ctrl+K')
        gen_action.triggered.connect(self.open_key_window)

        show_help = QtWidgets.QAction(QtGui.QIcon(), '&Справка', self)
        show_help.setShortcut('Ctrl+H')
        show_help.setStatusTip('Открыть справку')
        show_help.triggered.connect(self.show_dialog_help)

        convert = QtWidgets.QAction('Автоматически', self)
        n_convert = QtWidgets.QAction('Вручную', self)
        add_space = QtWidgets.QAction('Разделять байты', self)
        add_space.setCheckable(True)
        add_space.setChecked(False)
        add_space.triggered.connect(lambda: self.set_spacing(add_space.isChecked()))
        convert.setCheckable(True)
        convert.setChecked(True)
        n_convert.setCheckable(True)

        aes = QtWidgets.QAction('AES', self)
        gost = QtWidgets.QAction('ГОСТ 34.12', self)
        slf = QtWidgets.QAction('Самошифрование', self)
        aes.setCheckable(True)
        gost.setCheckable(True)
        aes.setChecked(True)
        slf.setCheckable(True)

        ecb = QtWidgets.QAction('ECB', self)
        ctr = QtWidgets.QAction('CTR', self)
        ofb = QtWidgets.QAction('OFB', self)
        cbc = QtWidgets.QAction('CBC', self)
        cfb = QtWidgets.QAction('CFB', self)
        ecb.setCheckable(True)
        ecb.setChecked(True)
        ctr.setCheckable(True)
        ofb.setCheckable(True)
        cbc.setCheckable(True)
        cfb.setCheckable(True)
        ecb.setStatusTip('Режим простой замены')
        ctr.setStatusTip('Режим гаммирования')
        ofb.setStatusTip('Режим гаммирования с обратной связью по выходу')
        cbc.setStatusTip('Режим простой замены с зацеплением')
        cfb.setStatusTip('Режим гаммирования с обратной связью по шифртексту')

        utf8 = QtWidgets.QAction('UTF-8', self)
        cp1251 = QtWidgets.QAction('windows-1251', self)
        utf8.setCheckable(True)
        cp1251.setCheckable(True)
        cp1251.setChecked(True)

        self.menu_bar = QtWidgets.QMenuBar()
        file_menu = self.menu_bar.addMenu('&Файл')
        file_menu.addAction(open_file)
        file_menu.addAction(save_action)
        file_menu.addSeparator()
        file_menu.addAction(exit_action)
        opt_menu = self.menu_bar.addMenu('&Правка')
        opt_menu.addAction(gen_action)
        alg_menu = opt_menu.addMenu('Алгоритм шифрования')
        alg_menu.addAction(aes)
        alg_menu.addAction(gost)
        alg_menu.addAction(slf)
        algorithm_menu = opt_menu.addMenu('Режим шифрования')
        algorithm_menu.addAction(ecb)
        algorithm_menu.addAction(ctr)
        algorithm_menu.addAction(ofb)
        algorithm_menu.addAction(cbc)
        algorithm_menu.addAction(cfb)
        convert_menu = opt_menu.addMenu('Перевод в байты')
        convert_menu.addAction(convert)
        convert_menu.addAction(n_convert)
        convert_menu.addAction(add_space)
        self.coding_menu = opt_menu.addMenu('Кодировка')
        self.coding_menu.addAction(utf8)
        self.coding_menu.addAction(cp1251)
        opt_menu.addSeparator()
        opt_menu.addAction(clear_action)
        self.menu_bar.addAction(open_settings_action)
        self.menu_bar.addAction(show_help)

        action_group = QtWidgets.QActionGroup(self)
        action_group.addAction(convert)
        action_group.addAction(n_convert)

        coding_group = QtWidgets.QActionGroup(self)
        coding_group.addAction(utf8)
        coding_group.addAction(cp1251)

        alg_group = QtWidgets.QActionGroup(self)
        alg_group.addAction(aes)
        alg_group.addAction(gost)
        alg_group.addAction(slf)

        algorithm_group = QtWidgets.QActionGroup(self)
        algorithm_group.addAction(ecb)
        algorithm_group.addAction(ctr)
        algorithm_group.addAction(ofb)
        algorithm_group.addAction(cbc)
        algorithm_group.addAction(cfb)

        utf8.triggered.connect(lambda: self.set_coding('utf-8'))
        cp1251.triggered.connect(lambda: self.set_coding('cp1251'))

        ecb.triggered.connect(lambda: self.set_algorithm('ECB'))
        ctr.triggered.connect(lambda: self.set_algorithm('CTR'))
        ofb.triggered.connect(lambda: self.set_algorithm('OFB'))
        cbc.triggered.connect(lambda: self.set_algorithm('CBC'))
        cfb.triggered.connect(lambda: self.set_algorithm('CFB'))

        convert.triggered.connect(lambda: self.set_convert(True))
        n_convert.triggered.connect(lambda: self.set_convert(False))

        aes.triggered.connect(lambda: self.set_alg('aes'))
        slf.triggered.connect(lambda: self.set_alg('self'))
        gost.triggered.connect(lambda: self.set_alg('gost'))

        self.keyLabel = QtWidgets.QLabel()
        self.keyLabel.setText("Ключ")

        self.text_edit = QtWidgets.QTextEdit(self)
        self.text_edit.textChanged.connect(self.str_to_bytes)
        self.hex_text_edit = QtWidgets.QTextEdit()
        self.hex_text_edit.textChanged.connect(self.bytes_to_str)
        self.text_result = QtWidgets.QTextEdit()
        self.hex_key_edit = QtWidgets.QLineEdit()
        self.hex_result = QtWidgets.QTextEdit()

        self.encode_btn = QtWidgets.QPushButton('', self)
        self.encode_btn.setIcon(QtGui.QIcon(resource_path('dec.png')))
        self.encode_btn.setStatusTip('Зашифровать')
        self.encode_btn.clicked.connect(self.encrypt)

        self.decode_btn = QtWidgets.QPushButton('', self)
        self.decode_btn.setIcon(QtGui.QIcon(resource_path('enc.png')))
        self.decode_btn.setStatusTip('Расшифровать')
        self.decode_btn.clicked.connect(self.decrypt)

        self.h_splitter_res = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        self.h_splitter_res.addWidget(self.text_result)
        self.h_splitter_res.addWidget(self.hex_result)

        self.h_splitter_data = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        self.h_splitter_data.addWidget(self.text_edit)
        self.h_splitter_data.addWidget(self.hex_text_edit)

        self.splitter_box_res = QtWidgets.QHBoxLayout()
        self.splitter_box_res.addWidget(self.h_splitter_res)

        self.splitter_box_data = QtWidgets.QHBoxLayout()
        self.splitter_box_data.addWidget(self.h_splitter_data)

        self.textGroup = QtWidgets.QGroupBox('Исходные данные')
        self.textGroup.setLayout(self.splitter_box_data)
        self.resGroup = QtWidgets.QGroupBox('Результат')
        self.resGroup.setLayout(self.splitter_box_res)

        self.h_main_box = QtWidgets.QHBoxLayout()

        self.file_v_box = QtWidgets.QVBoxLayout()
        self.widget_layout = QtWidgets.QWidget()
        self.widget_layout_f = QtWidgets.QWidget()
        self.v_box = QtWidgets.QVBoxLayout()
        self.h_box = QtWidgets.QHBoxLayout()
        self.key_h_box = QtWidgets.QHBoxLayout()

        self.h_box.addWidget(self.encode_btn)
        self.h_box.addWidget(self.decode_btn)
        self.key_h_box.addWidget(self.keyLabel)
        self.key_h_box.addWidget(self.hex_key_edit)
        self.key_h_box.addLayout(self.h_box)
        self.v_box.addLayout(self.key_h_box)

        self.v_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        self.v_splitter.addWidget(self.textGroup)
        self.v_splitter.addWidget(self.resGroup)

        self.splitter_box_main = QtWidgets.QHBoxLayout()
        self.splitter_box_main.addWidget(self.v_splitter)

        self.path_h_box = QtWidgets.QHBoxLayout()
        self.path_h_box.addWidget(QtWidgets.QLabel('Путь к файлу:'))
        self.path_edit = QtWidgets.QLineEdit()
        self.path_btn = QtWidgets.QPushButton(QtGui.QIcon(resource_path('open.png')), "")
        self.path_btn.setStatusTip('Выбрать файл для шифрования')
        self.path_btn.clicked.connect(self.choose_file)
        self.path_h_box.addWidget(self.path_edit)
        self.path_h_box.addWidget(self.path_btn)
        self.result_edit = QtWidgets.QTextEdit()
        self.result_edit.setReadOnly(True)
        self.progress_bar = QtWidgets.QProgressBar(self)
        self.progress_bar.setRange(0, 100)
        self.file_v_box.addLayout(self.path_h_box)
        self.file_v_box.addWidget(self.progress_bar)
        self.file_v_box.addWidget(self.result_edit)

        self.tab = QtWidgets.QTabWidget()
        self.widget_layout.setLayout(self.splitter_box_main)
        self.widget_layout_f.setLayout(self.file_v_box)
        self.tab.addTab(self.widget_layout, "Текст")
        self.tab.addTab(self.widget_layout_f, "Файл")
        self.v_box.addWidget(self.tab)
        self.tab.setCurrentIndex(1)
        self.h_main_box.addLayout(self.v_box)
        self.setLayout(self.h_main_box)

        self.convert = True
        self.space = False
        self.coding = 'cp1251'
        self.algorithm = 'ECB'
        self.alg = 'aes'

        self.enc_thread = EncThread(self)
        self.enc_thread.finished.connect(lambda: self.set_result(f'Шифрование файла {self.enc_thread.f_name} '
                                                                 f'завершено'))

        self.dec_thread = DecThread(self)
        self.dec_thread.finished.connect(lambda: self.set_result(f'Расшифрование файла {self.dec_thread.f_name} '
                                                                 f'завершено'))

        self.enc_thread_self = EncThreadSelf(self)
        self.enc_thread_self.finished.connect(lambda: self.set_result(f'Шифрование файла {self.enc_thread.f_name} '
                                                                      f'завершено'))

        self.dec_thread_self = DecThreadSelf(self)
        self.dec_thread_self.finished.connect(lambda: self.set_result(f'Расшифрование файла {self.dec_thread.f_name} '
                                                                      f'завершено'))

    def ch_value(self, value):
        self.progress_bar.setValue(int(value) % 101)

    def set_coding(self, coding):
        self.coding = coding

    def set_spacing(self, is_checked):
        self.space = is_checked

    def set_alg(self, alg):
        self.alg = alg
        if self.alg == 'self':
            self.hex_key_edit.setDisabled(True)
        else:
            self.hex_key_edit.setEnabled(True)

    def set_algorithm(self, algorithm):
        self.algorithm = algorithm
        if algorithm == 'OFB' or algorithm == 'CTR':
            if not self.decode_btn.isHidden():
                self.decode_btn.hide()
                self.encode_btn.setIcon(QtGui.QIcon(resource_path('enc_dec.png')))
                self.encode_btn.setStatusTip('Зашифровать / Расшифровать')
        else:
            if self.decode_btn.isHidden():
                self.decode_btn.show()
                self.encode_btn.setIcon(QtGui.QIcon(resource_path('dec.png')))
                self.encode_btn.setStatusTip('Зашифровать')

    def set_convert(self, boolean):
        self.convert = boolean
        if not self.convert:
            self.text_edit.blockSignals(True)
            self.hex_text_edit.blockSignals(True)
            self.coding_menu.setDisabled(True)
            self.text_edit.hide()
        else:
            self.text_edit.blockSignals(False)
            self.hex_text_edit.blockSignals(False)
            self.coding_menu.setDisabled(False)
            self.text_edit.show()

    def generate(self):
        if self.hex_key_edit.text() == '':
            for _ in range(32):
                q = random.randint(32, 126)
                self.hex_key_edit.insert(hex(q)[2:])
        else:
            m = self.hex_key_edit.text()
            h = hashlib.sha256(m.encode())
            self.hex_key_edit.clear()
            self.hex_key_edit.setText(h.hexdigest())

    def choose_file(self):
        try:
            f_name = QtWidgets.QFileDialog.getOpenFileName(self, 'Open file', os.path.join('D:\\', ''))[0]
            self.path_edit.setText(f_name)
        except FileNotFoundError:
            self.error("Выберите файл")

    def show_dialog_open(self):
        print('run')
        f_name = QtWidgets.QFileDialog.getOpenFileName(self, 'Open file', '')[0]
        try:
            f = open(f_name, 'r', encoding=self.coding)
            with f:
                data = f.read()
                self.text_edit.setText(data)
        except FileNotFoundError:
            self.error("Выберите файл")
        except UnicodeDecodeError:
            self.error("Данный формат файла не поддерживается!")
        except:
            self.error("Ошибка открытия файла, пожалуйста, введите данные в поддерживаемом формате")

    def export(self):
        try:
            hex_res = self.hex_result.toPlainText()

            f = QtWidgets.QFileDialog.getSaveFileName(self, "Save To File", "", "Text Files (*.txt)", options=options)
            file_name = f[0]
            write_file = open(file_name, 'w', encoding=self.coding)
            with write_file:
                write_file.write(hex_res)
        except FileNotFoundError:
            self.error("Выберите файл")
        except UnicodeDecodeError:
            self.error("Данный формат файла не поддерживается!")

    def show_dialog_help(self):
        text = open('text', 'rb').read().decode()
        dialog = QtWidgets.QMessageBox(QtWidgets.QMessageBox.Information, "Справка", text,
                                       buttons=QtWidgets.QMessageBox.Ok, parent=self)
        dialog.exec()

    def decrypt(self):
        if self.hex_key_edit.text() == '':
            key_window = KeyWindow(self)
            result = key_window.exec_()
            if result:
                secret = key_window.key_edit.text()
                h = hashlib.sha256(secret.encode())
                self.hex_key_edit.setText(h.hexdigest())
        elif len(self.hex_key_edit.text()) != 64:
            self.error('Размер ключа не равен 256 бит')
            return
        else:
            if self.tab.currentIndex() == 1:
                if self.alg == 'gost' or self.alg == 'aes':
                    f_name = self.path_edit.text()
                    if not f_name:
                        self.error('Выберите файл')
                        return
                    self.result_edit.setText(f'Расшифрование файла: {f_name}')
                    self.dec_thread.set_f_name(f_name)
                    self.dec_thread.set_alg(self.alg)
                    self.dec_thread.start()
                else:
                    f_name = self.path_edit.text()
                    if not f_name:
                        self.error('Выберите файл')
                        return
                    self.result_edit.setText(f'Расшифрование файла: {f_name}')

                    self.dec_thread_self.set_f_name(f_name)
                    self.dec_thread_self.start()
            else:
                if self.alg == 'gost' or self.alg == 'aes':
                    string = self.hex_text_edit.toPlainText()
                    try:
                        data = bytearray().fromhex(string)
                    except Exception as e:
                        self.error('invalid data!\n' + str(e))
                        return
                    self.text_result.clear()
                    self.hex_result.clear()
                    try:
                        key = bytes.fromhex(self.hex_key_edit.text())
                    except Exception as e:
                        self.error('invalid key!\n' + str(e))
                        return
                    if self.alg == 'gost':
                        try:
                            result = self.block_cipher.decrypt(data, key, self.algorithm)
                        except Exception as e:
                            self.error('Ошибка длинны блока!\n' + str(e))
                            return
                    else:
                        try:
                            result = self.aes_cipher.decrypt(data, key, self.algorithm)
                        except Exception as e:
                            self.error('Ошибка длинны блока!\n' + str(e))
                            return
                    if not result:
                        self.error('Введите параметры режима шифрования')
                        return
                    else:
                        res = ''
                        for b in result:
                            res += hex(b)[2:].rjust(2, '0')
                            if self.space:
                                res += ' '
                        self.hex_result.insertPlainText(res)
                        try:
                            self.text_result.setText(result.decode(self.coding))
                        except:
                            for elem in result:
                                self.text_result.insertPlainText(chr(elem))
                else:
                    string = self.hex_text_edit.toPlainText()
                    data = bytearray().fromhex(string)
                    self.text_result.clear()
                    self.hex_result.clear()

                    result = b''
                    result += int.to_bytes(data[0], 1, 'big')
                    for i in range(1, len(data)):
                        result += int.to_bytes(data[i] ^ data[i - 1], 1, 'big')

                    res = ''
                    for b in result:
                        res += hex(b)[2:].rjust(2, '0')
                        if self.space:
                            res += ' '
                    self.hex_result.insertPlainText(res)
                    try:
                        self.text_result.setText(result.decode(self.coding))
                    except:
                        for elem in result:
                            self.text_result.insertPlainText(chr(elem))

    def encrypt(self):
        if self.hex_key_edit.text() == '':
            key_window = KeyWindow(self)
            result = key_window.exec_()
            if result:
                secret = key_window.key_edit.text()
                h = hashlib.sha256(secret.encode())
                self.hex_key_edit.setText(h.hexdigest())
        elif len(self.hex_key_edit.text()) != 64:
            self.error('Размер ключа не равен 256 бит')
            return
        else:
            if self.tab.currentIndex() == 1:
                f_name = self.path_edit.text()
                if not f_name:
                    self.error('Выберите файл')
                    return
                self.result_edit.setText(f'Шифрование файла: {f_name}')
                self.enc_thread.set_alg(self.alg)
                self.enc_thread.set_f_name(f_name)
                self.enc_thread.start()
            else:
                if self.alg == 'gost' or self.alg == 'aes':
                    string = self.hex_text_edit.toPlainText()
                    try:
                        data = bytearray().fromhex(string)
                    except Exception as e:
                        self.error('invalid data!\n' + str(e))
                        return
                    self.text_result.clear()
                    self.hex_result.clear()
                    try:
                        key = bytes.fromhex(self.hex_key_edit.text())
                    except Exception as e:
                        self.error('invalid key!\n' + str(e))
                        return
                    if self.alg == 'gost':
                        result = self.block_cipher.encrypt(data, key, self.algorithm)
                    else:
                        result = self.aes_cipher.encrypt(data, key, self.algorithm)
                    if not result:
                        self.error('Введите параметры режима шифрования')
                        return
                    else:
                        res = ''
                        for b in result:
                            res += hex(b)[2:].rjust(2, '0')
                            if self.space:
                                res += ' '
                        self.hex_result.insertPlainText(res)
                        try:
                            self.text_result.setText(result.decode(self.coding))
                        except:
                            for elem in result:
                                self.text_result.insertPlainText(chr(elem))

                else:
                    string = self.hex_text_edit.toPlainText()
                    data = bytearray().fromhex(string)
                    self.text_result.clear()
                    self.hex_result.clear()

                    result = b''
                    result += int.to_bytes(data[0], 1, 'big')
                    for i in range(1, len(data)):
                        result += int.to_bytes(data[i] ^ result[i - 1], 1, 'big')

                    res = ''
                    for b in result:
                        res += hex(b)[2:].rjust(2, '0')
                        if self.space:
                            res += ' '
                    self.hex_result.insertPlainText(res)
                    try:
                        self.text_result.setText(result.decode(self.coding))
                    except:
                        for elem in result:
                            self.text_result.insertPlainText(chr(elem))

    def clear(self):
        self.hex_key_edit.clear()
        self.text_edit.clear()
        self.hex_text_edit.clear()
        self.text_result.clear()
        self.hex_result.clear()

    def set_result(self, text):
        self.result_edit.setText(text)

    def bytes_to_str(self):
        if self.convert:
            self.text_edit.blockSignals(True)

        self.text_edit.clear()
        string = self.hex_text_edit.toPlainText()
        try:
            bytes = bytearray().fromhex(string)
            self.text_edit.insertPlainText(bytes.decode(self.coding))
        except:
            self.text_edit.insertPlainText('invalid data!')
        if self.convert:
            self.text_edit.blockSignals(False)

    def str_to_bytes(self):
        if self.convert:
            self.hex_text_edit.blockSignals(True)
        try:
            self.hex_text_edit.clear()
            string = self.text_edit.toPlainText()
            byte_string = string.encode(self.coding)
            res = ''
            for b in byte_string:
                res += hex(b)[2:].rjust(2, '0')
                if self.space:
                    res += ' '
            self.hex_text_edit.setText(res)
        except:
            if self.convert:
                self.hex_text_edit.blockSignals(False)
        if self.convert:
            self.hex_text_edit.blockSignals(False)

    def open_settings(self):
        setting_window = SettingWindow(self)
        result = setting_window.exec_()
        if result:
            self.block_cipher.cfb_dict['s'] = setting_window.cfb_wid.s_param_edit.value()
            self.block_cipher.cfb_dict['m'] = setting_window.cfb_wid.m_param_edit.value()
            self.block_cipher.cfb_dict['syncro'] = setting_window.cfb_wid.syncro_edit.text()
            self.block_cipher.ctr_dict['s'] = setting_window.ctr_wid.s_param_edit.value()
            self.block_cipher.ctr_dict['syncro'] = setting_window.ctr_wid.syncro_edit.text()
            self.block_cipher.ofb_dict['s'] = setting_window.ofb_wid.s_param_edit.value()
            self.block_cipher.ofb_dict['z'] = setting_window.ofb_wid.z_param_edit.value()
            self.block_cipher.ofb_dict['syncro'] = setting_window.ofb_wid.syncro_edit.text()
            self.block_cipher.cbc_dict['z'] = setting_window.cbc_wid.z_param_edit.value()
            self.block_cipher.cbc_dict['syncro'] = setting_window.cbc_wid.syncro_edit.text()

    def open_key_window(self):
        key_window = KeyWindow(self)
        result = key_window.exec_()
        if result:
            secret = key_window.key_edit.text()
            h = hashlib.sha256(secret.encode())
            self.hex_key_edit.setText(h.hexdigest())

    def closeEvent(self, event):
        reply = QtWidgets.QMessageBox.question(self, 'Выйти', "Вы уверены что хотите выйти?",
                                               QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                                               QtWidgets.QMessageBox.No)
        if reply == QtWidgets.QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()

    def error(self, text):
        dialog = QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, "Ошибка!", text,
                                       buttons=QtWidgets.QMessageBox.Ok, parent=self)
        dialog.exec()


class EncThread(QtCore.QThread):
    def __init__(self, parent=None, f_name=None):
        super().__init__(parent=parent)

        self.parent = parent
        self.f_name = f_name
        self.alg = None

    def set_f_name(self, f_name):
        self.f_name = f_name

    def set_alg(self, alg):
        self.alg = alg

    def run(self):
        try:
            key = bytes.fromhex(self.parent.hex_key_edit.text())
        except Exception as e:
            self.parent.error('invalid key!\n' + str(e))
            return
        try:
            f = open(self.f_name, 'rb')
            with f:
                data = bytearray(f.read())
                if self.alg == 'gost':
                    enc_data = self.parent.block_cipher.encrypt(data, key, self.parent.algorithm)
                else:
                    enc_data = self.parent.aes_cipher.encrypt(data, key, self.parent.algorithm)
                if not enc_data:
                    return

            f = open(f'{self.f_name}.enc', 'wb')
            with f:
                f.write(enc_data)
        except Exception as e:
            print(e)
            return


class EncThreadSelf(EncThread):
    def __init__(self, parent=None, f_name=None):
        super().__init__(parent=parent, f_name=f_name)

    def run(self):
        with open(self.f_name, 'rb') as f:
            data_orig = f.read()

        b = b''
        b += int.to_bytes(data_orig[0], 1, 'big')
        for i in range(1, len(data_orig)):
            b += int.to_bytes(data_orig[i] ^ b[i - 1], 1, 'big')

        with open(f'{self.f_name}.enc', 'wb') as f:
            f.write(b)


class DecThread(QtCore.QThread):
    def __init__(self, parent=None, f_name=None):
        super().__init__(parent=parent)

        self.parent = parent
        self.f_name = f_name
        self.alg = None

    def set_f_name(self, f_name):
        self.f_name = f_name

    def set_alg(self, alg):
        self.alg = alg

    def run(self):
        try:
            key = bytes.fromhex(self.parent.hex_key_edit.text())
        except Exception as e:
            self.parent.error('invalid key!\n' + str(e))
            return
        try:
            f = open(self.f_name, 'rb')
            with f:
                data = bytearray(f.read())
                if self.alg == 'gost':
                    dec_data = self.parent.block_cipher.decrypt(data, key, self.parent.algorithm)
                else:
                    dec_data = self.parent.aes_cipher.decrypt(data, key, self.parent.algorithm)
                if not dec_data:
                    return
            if self.f_name.split(".")[-1] == 'enc':
                f = open('.'.join(self.f_name.split(".")[:-1]), 'wb')
            else:
                f = open(self.f_name + '_decrypted', 'wb')
            with f:
                f.write(dec_data)

        except Exception as e:
            print(e)
            return


class DecThreadSelf(DecThread):
    def __init__(self, parent=None, f_name=None):
        super().__init__(parent=parent, f_name=f_name)

    def run(self):
        with open(self.f_name, 'rb') as f:
            data_enc = f.read()

        b = b''
        b += int.to_bytes(data_enc[0], 1, 'big')
        for i in range(1, len(data_enc)):
            b += int.to_bytes(data_enc[i] ^ data_enc[i - 1], 1, 'big')
        with open('.'.join(self.f_name.split(".")[:-1]), 'wb') as f:
            f.write(b)


class SettingWindow(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent=parent, flags=QtCore.Qt.Tool)

        self.setWindowTitle('Параметры режимов шифрования')

        self.ctr_wid = TabWidgets.OptionWidget(s=parent.block_cipher.ctr_dict['s'],
                                               syncro=parent.block_cipher.ctr_dict['syncro'])
        self.ofb_wid = TabWidgets.OptionWidget(z=parent.block_cipher.ofb_dict['z'], s=parent.block_cipher.ofb_dict['s'],
                                               syncro=parent.block_cipher.ofb_dict['syncro'])
        self.cbc_wid = TabWidgets.OptionWidget(z=parent.block_cipher.cbc_dict['z'],
                                               syncro=parent.block_cipher.cbc_dict['syncro'])
        self.cfb_wid = TabWidgets.OptionWidget(s=parent.block_cipher.cfb_dict['s'], m=parent.block_cipher.cfb_dict['m'],
                                               syncro=parent.block_cipher.cfb_dict['syncro'])
        self.tab = QtWidgets.QTabWidget()
        self.tab.addTab(self.ctr_wid, 'CTR')
        self.tab.addTab(self.ofb_wid, 'OFB')
        self.tab.addTab(self.cbc_wid, 'CBC')
        self.tab.addTab(self.cfb_wid, 'CFB')
        v_box = QtWidgets.QVBoxLayout()
        accept_btn = QtWidgets.QPushButton('Принять')
        accept_btn.clicked.connect(self.accept)
        v_box.addWidget(self.tab)
        v_box.addWidget(accept_btn, alignment=QtCore.Qt.AlignRight)
        self.setLayout(v_box)
        self.resize(840, 200)


class KeyWindow(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent=parent, flags=QtCore.Qt.Tool)

        self.setWindowTitle('Мастер ключей')

        self.form = QtWidgets.QFormLayout()
        self.key_edit = QtWidgets.QLineEdit()
        accept_btn = QtWidgets.QPushButton('Применить')
        accept_btn.clicked.connect(self.accept)

        self.form.addRow('Секрет:', self.key_edit)
        self.form.addWidget(accept_btn)
        self.setLayout(self.form)


if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)

    window = QtWidgets.QMainWindow()
    widget = MainWidget()
    window.setCentralWidget(widget)
    window.setMenuBar(widget.menu_bar)
    window.setWindowIcon(QtGui.QIcon(resource_path('dec.png')))
    window.setWindowTitle("Шифратор")
    window.setStatusBar(QtWidgets.QStatusBar())
    screen = app.primaryScreen()
    size = screen.size()
    window.setGeometry(QtCore.QRect(int(size.width() / 2) - 360, int(size.height() / 2) - 210, 720, 420))
    window.show()

    sys.exit(app.exec_())
