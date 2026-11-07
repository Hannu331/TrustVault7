from ..core.database import get_connection

def get_document(document_id):
    c=get_connection(); r=c.execute('SELECT * FROM documents WHERE id=?',(document_id,)).fetchone(); c.close(); return dict(r) if r else None

def visible_documents(user):
    c=get_connection()
    if user['role']=='administrator': rows=c.execute('SELECT * FROM documents ORDER BY id DESC').fetchall()
    else: rows=c.execute("SELECT DISTINCT d.* FROM documents d LEFT JOIN permissions p ON p.document_id=d.id AND p.username=? WHERE d.owner_username=? OR p.access IN ('READ','EDIT') ORDER BY d.id DESC",(user['username'],user['username'])).fetchall()
    c.close(); return [dict(r) for r in rows]

def can_access(user,document_id,required='READ'):
    d=get_document(document_id)
    if not d: return False
    if user['role']=='administrator' or d['owner_username']==user['username']: return True
    c=get_connection(); r=c.execute('SELECT access FROM permissions WHERE document_id=? AND username=?',(document_id,user['username'])).fetchone(); c.close()
    return bool(r and ((required=='EDIT' and r['access']=='EDIT') or (required=='READ' and r['access'] in ('READ','EDIT'))))
