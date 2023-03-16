# getting member id from auth token
def get_member_id(request):
    if request.auth:
        return request.auth['user_id']
    return None
