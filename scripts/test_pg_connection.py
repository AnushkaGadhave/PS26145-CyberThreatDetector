import psycopg2

passwords_to_test = ['postgres', 'admin', 'root', '123456', '', 'password', 'Anushka', 'anushka']
success_conn = None

for pwd in passwords_to_test:
    try:
        conn = psycopg2.connect(
            host='127.0.0.1',
            port=5432,
            user='postgres',
            password=pwd,
            dbname='postgres',
            connect_timeout=2
        )
        print(f'Connected successfully to PostgreSQL with password: "{pwd}"')
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute("SELECT 1;")
        cur.execute("SELECT 1 FROM pg_database WHERE datname='cyber_threats';")
        if not cur.fetchone():
            cur.execute("CREATE DATABASE cyber_threats;")
            print('Created database cyber_threats.')
        else:
            print('Database cyber_threats already exists.')
        conn.close()
        success_conn = pwd
        break
    except Exception as e:
        print(f'Attempt with password "{pwd}" failed: {e}')

if success_conn is not None:
    print(f'PostgreSQL ready. Working password: "{success_conn}"')
else:
    print('No default password matched.')
