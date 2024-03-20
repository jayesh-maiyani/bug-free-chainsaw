# Client Portal Backend

## 1. Create environment
- <code>python -m venv env</code>
- <code>source ./env/bin/activate</code>

## 2. Install requirements
- <code>pip install -r requirements.txt</code>

## 3. Find setting.py here
- <code>fds_client/fds_client/settings.py</code>

## 4. Try migrating using existing migrations
- <code>./manage.py makemigrations</code>
- <code>./manage.py migrate</code>

### Note: if no error jump to step 5
- <code>./manage.py makemigrations --fake</code> only when DBMS column exists or not exists error appear, as the migrations are performed on all the three different portals

## 5. Run the server
- <code>./manage.py runserver</code> or run the server using gunicorn, uvicorn, daphne whichever suits.
