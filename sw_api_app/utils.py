import threading
import smtplib
import avinit

from django.utils.safestring import mark_safe
from django.template.loader import render_to_string
from django.utils import timezone
from django.core.files.base import File

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from SHOCK_WAVE.settings import EMAIL_PORT, EMAIL_HOST, EMAIL_HOST_USER, EMAIL_HOST_PASSWORD


# getting member id from auth token
def get_member_id(request):
    if request.auth:
        return request.auth['user_id']
    return None


class SendMailNotification(threading.Thread):
    def __init__(self, otp, user):
        self.otp = otp
        self.user = user
        threading.Thread.__init__(self)

    def run(self) -> None:
        try:
            mail_to = self.user.email
            user_name = self.user.first_name + " " + self.user.last_name
            context = {'name': user_name,
                       'otp': self.otp}
            sender = 'abinaya@zaigoinfotech.com'
            recipients = [mail_to]
            subject = 'Reg: ShockWave Password Reset'
            message = mark_safe(render_to_string('email/user_reset_password.html', context))

            # Create the message object
            msg = MIMEMultipart()
            msg['From'] = sender
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = subject
            msg.attach(MIMEText(message, 'html'))
            with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
                server.starttls()
                server.login(EMAIL_HOST_USER, EMAIL_HOST_PASSWORD)
                server.sendmail(sender, recipients, msg.as_string())

        except Exception as e:
            print("error:", str(e))
            pass
        return


def get_attachment_from_name(member_name):
    avinit.get_png_avatar(member_name, output_file='media/tmp.png')
    file_name = f"media/MEM_{member_name}{timezone.now().strftime('%Y%m%d%s%f')}.png"
    return File(file=open("media/tmp.png", 'rb'), name=file_name)
