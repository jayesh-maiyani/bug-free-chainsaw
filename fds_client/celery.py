# celery.py

import os
from celery import Celery

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'fds_client.settings')

app = Celery('fds_client')

# Read Celery configuration from Django settings file
app.config_from_object('django.conf:settings', namespace='CELERY')

# Discover and register tasks in Django apps
app.autodiscover_tasks()
