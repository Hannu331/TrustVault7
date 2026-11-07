from datetime import datetime
from ..core.database import get_connection

def grant_permission(document_id,username,access,granted_by):
    if access not in ('READ','EDIT'): raise ValueError('Access must be READ or EDIT')
    c=get_connection(); c.execute('INSERT INTO permissions(document_id,username,access,granted_by,granted_at) VALUES(?,?,?,?,?) ON CONFLICT(document_id,username) DO UPDATE SET access=excluded.access,granted_by=excluded.granted_by,granted_at=excluded.granted_at',(document_id,username,access,granted_by,datetime.utcnow().isoformat())); c.commit(); c.close()

def revoke_permission(document_id,username):
    c=get_connection(); c.execute('DELETE FROM permissions WHERE document_id=? AND username=?',(document_id,username)); c.commit(); c.close()
