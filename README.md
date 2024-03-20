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

## 5. create subscription_plan models from fixtures 
- <code>manage.py loaddata subscription_plan</code>

### Note: if no error jump to step 7

## else:
- Comment <code>plan</code> field from <code>models.py</code> of accounts application

- <code>./manage.py makemigrations</code>
- <code>./manage.py migrate</code>

### Note: Errors, if any, just get the file name from error trace and uncomment the file

- Now uncomment <code>Notification</code> model from <code>accounts/models.py</code>
- Also uncomment <code>Transaction</code> model from <code>subscription/models.py</code>


- <code>./manage.py makemigrations</code>
- <code>./manage.py migrate</code>

- Now uncomment every commented file from before

## 7. Run <code>./manage.py collectstatic</code>

## 10. Configure celery and redis
- <code>pip install celery redis</code>
- Open a terminal and navigate to our Django project's root directory.
- start redis server on port 8005
- <code>redis-server --port 8005</code>
- Run the following command to start the Celery worker:
- <code>celery -A fds_client worker --loglevel=info</code>
