from datetime import datetime
from ..core.database import get_connection

def log_event(actor,action,target,details=''):
    c=get_connection(); c.execute('INSERT INTO audit_logs(actor,action,target,details,timestamp) VALUES(?,?,?,?,?)',(actor,action,target,details,datetime.utcnow().isoformat())); c.commit(); c.close()
