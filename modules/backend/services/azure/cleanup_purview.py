import sqlite3
import json
import requests
import time

def get_token(tenant, cid, secret):
    url = f'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token'
    data = {
        'client_id': cid,
        'client_secret': secret,
        'scope': 'https://graph.microsoft.com/.default',
        'grant_type': 'client_credentials'
    }
    r = requests.post(url, data=data)
    if r.status_code != 200:
        raise Exception(f"Auth failed: {r.text}")
    return r.json().get('access_token')

def main():
    print("[CLEANUP] Connecting to database...")
    try:
        conn = sqlite3.connect('/app/data/mssp.db')
        row = conn.cursor().execute("SELECT value FROM frontend_config WHERE key='cloud'").fetchone()
        if not row:
            print("[ERROR] Cloud config not found in database.")
            return
            
        azure = json.loads(row[0]).get('azure', {})
        tenant = azure.get('tenant_id')
        cid = azure.get('client_id')
        secret = azure.get('client_secret')
        
        if not all([tenant, cid, secret]):
            print("[ERROR] Missing Azure credentials in config.")
            return

        print("[CLEANUP] Fetching access token...")
        token = get_token(tenant, cid, secret)
        headers = {'Authorization': f'Bearer {token}'}
        
        # 1. List all queries
        base_url = 'https://graph.microsoft.com/beta/security/auditLog/queries'
        print(f"[CLEANUP] Listing queries from {base_url}...")
        r = requests.get(base_url, headers=headers)
        
        if r.status_code != 200:
            print(f"[ERROR] Failed to list queries: {r.status_code} - {r.text}")
            return
            
        queries = r.json().get('value', [])
        print(f"[CLEANUP] Found {len(queries)} queries.")
        
        # 2. Delete each one
        deleted_count = 0
        failed_count = 0
        
        for q in queries:
            qid = q.get('id')
            print(f"  Deleting {qid} (Status: {q.get('status')})...", end='', flush=True)
            
            del_url = f"{base_url}('{qid}')"
            dr = requests.delete(del_url, headers=headers)
            
            if dr.status_code in (200, 204):
                print(" SUCCESS")
                deleted_count += 1
            else:
                print(f" FAILED ({dr.status_code}) - {dr.text}")
                failed_count += 1
            
            # Small sleep to avoid throttling the DELETE bucket
            time.sleep(0.5)
            
        print(f"\n[CLEANUP] Summary: {deleted_count} deleted, {failed_count} failed.")
        
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")

if __name__ == "__main__":
    main()
