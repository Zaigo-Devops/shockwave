import threading
import smtplib
import avinit
from django.core.paginator import Paginator
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
    file_name = f"MEM_{member_name}{timezone.now().strftime('%Y%m%d%s%f')}.png"
    avinit.get_png_avatar(member_name, output_file=f"media/{file_name}")
    return File(file=open(f"media/{file_name}", 'rb'), name=file_name)


def get_paginated_response(queryset, url, page_number, limit, extras=None, empty=False):
    try:
        if empty or queryset.count() == 0:
            return {
                "links": {
                    "next": None,
                    "previous": None
                },
                "per_page": limit,
                "page": page_number,
                "total_pages": 0,
                "total": 0,
                "data": []
            }
        join_word = '?'
        if join_word in url:
            url = url.rpartition(join_word)[0]
        if not extras:
            extras = {}
        paginate = Paginator(queryset, limit)
        page = paginate.page(page_number)
        data = page.object_list
        paginated_response = {
            "per_page": limit,
            "page": page_number,
            "total_pages": paginate.num_pages,
            "total": paginate.count,
            "data": data
        }
        return paginated_response
    except Exception as e:
        return {
            "links": {
                "next": None,
                "previous": None
            },
            "per_page": limit,
            "page": page_number,
            "total_pages": 0,
            "total": 0,
            "data": [],
            "message": str(e)
        }


def generate_user_cards(queryset, is_many=False):
    if is_many:
        records = []
        for record in queryset:
            records.append(generate_user_card(record))
        return records
    return generate_user_card(queryset)


def generate_user_card(obj):
    session_data = {
        "session_data_id": obj.pk,
        "device_serial_no": obj.device_id.device_serial_no,
        "device_name": obj.device_id.device_name,
        "session_id": obj.session_id.pk,
        "environment": obj.session_id.environment,
        "location": obj.session_id.location,
        "energy_levels": obj.energy_data,
        "lowest_energy_level": obj.lowest_energy_level,
        "highest_energy_level": obj.highest_energy_level,
        "created_at": obj.created_at
    }
    return session_data
