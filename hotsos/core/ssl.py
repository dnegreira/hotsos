from hotsos.core.log import log
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime


class SSLCertificate(object):

    """
    This class instantiates an SSLCertificate object.
    """

    def __init__(self, certificate_path):
        """
        @param certificate_path: path to the certificate that we want to load
        in order to gather information from.
        If the file in the path fails to read, it raises an exception.
        """
        self.certificate_path = certificate_path
        try:
            with open(self.certificate_path, "rb") as fd:
                self.certificate = fd.read()
        except OSError:
            log.debug("Unable to read SSL certificate file %s",
                      self.certificate_path)
            raise

    @property
    def certificate_expire_date(self):
        "return datetime() of when the certificate expires"
        cert = x509.load_pem_x509_certificate(self.certificate,
                                              default_backend())
        return cert.not_valid_after

    @property
    def certificate_days_to_expire(self):
        "return int(days) remaining until the certificate expires"
        today = datetime.today()
        certificate_date = self.certificate_expire_date
        days_to_expire = certificate_date - today
        return int(days_to_expire.days)

    @property
    def path(self):
        "return str(path) where the certificate file is located"
        return str(self.certificate_path)