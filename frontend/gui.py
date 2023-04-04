from backend.ssl_checker import SSLChecker
from backend.ssl_checker_exceptions import SSLCertificateError

class SSLCheckerApp(App):
    def build(self):
        layout = GridLayout(cols=2)

        layout.add_widget(Label(text='Enter URL:'))
        self.url_input = TextInput()
        layout.add_widget(self.url_input)

        layout.add_widget(Label(text='Certificate Information:'))
        self.cert_info = Label(text='')
        layout.add_widget(self.cert_info)

        self.check_button = Button(text='Check Certificate')
        self.check_button.bind(on_press=self.check_certificate)
        layout.add_widget(self.check_button)

        return layout

    def check_certificate(self, instance):
        url = self.url_input.text

        try:
            ssl_checker = SSLChecker(url)
            cert_info = ssl_checker.get_cert_info()
            self.cert_info.text = str(cert_info)
        except SSLCertificateError:
            self.cert_info.text = 'Error: Invalid SSL certificate or URL'
