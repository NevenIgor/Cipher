from PyQt5 import QtWidgets


class OptionWidget(QtWidgets.QWidget):
    def __init__(self, z=None, s=None, m=None, syncro=None):
        super().__init__()

        self.z_param_edit = QtWidgets.QSpinBox()
        self.z_param_edit.setMinimum(1)

        self.m_param_edit = QtWidgets.QSpinBox()
        self.m_param_edit.setRange(128, 1024)

        self.s_param_edit = QtWidgets.QSpinBox()
        self.s_param_edit.setRange(8, 128)
        self.s_param_edit.setSingleStep(8)

        self.syncro_edit = QtWidgets.QLineEdit()
        self.syncro_edit.textChanged.connect(self.set_len)
        self.syncro_len = QtWidgets.QLabel()
        self.syncro_need = QtWidgets.QLabel()

        self.form = QtWidgets.QFormLayout()
        self.correct = ('<span style="color: green; font-size: 14pt;">&#x2714;</span>',
                        '<span style="color: red; font-size: 14pt;">&#x2718;</span>')
        self.form.addRow('Текущее значение синхропосылки:', self.syncro_len)
        self.form.addRow('Требуемое значение синхропосылки:', self.syncro_need)
        if s and not m and not z:
            self.syncro_need.setText(str(int(128 / 2)))
        if s and z:
            self.syncro_need.setText(str(int(128 * self.z_param_edit.value())))
            self.z_param_edit.valueChanged.connect(self.z_param_changed)
        if z and not s:
            self.syncro_need.setText(str(int(128 * self.z_param_edit.value())))
            self.z_param_edit.valueChanged.connect(self.z_param_changed)
        self.form.addRow('Синхропосылка:', self.syncro_edit)
        if syncro:
            self.syncro_edit.setText(syncro)
        if s:
            self.form.addRow('Параметр S:', self.s_param_edit)
            self.s_param_edit.setValue(s)
        if z:
            self.form.addRow('Параметр Z:', self.z_param_edit)
            self.z_param_edit.setValue(z)
        if m:
            self.form.addRow('Параметр M:', self.m_param_edit)
            self.m_param_edit.setValue(m)
            self.syncro_need.setText(str(m))
            self.m_param_edit.valueChanged.connect(self.m_param_changed)

        self.setLayout(self.form)

    def set_len(self):
        if len(self.syncro_edit.text()) % 2 == 0:
            self.syncro_len.setText(str(int(len(self.syncro_edit.text()) * 4)))

    def z_param_changed(self):
        self.syncro_need.setText(str(int(128 * self.z_param_edit.value())))

    def m_param_changed(self):
        self.syncro_need.setText(str(self.m_param_edit.value()))

