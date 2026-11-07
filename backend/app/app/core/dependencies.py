from fastapi import Request

def current_user(request): return request.session.get('user')
def require_login(request): return current_user(request)
def require_admin(request):
    u=current_user(request); return u if u and u.get('role')=='administrator' else None
