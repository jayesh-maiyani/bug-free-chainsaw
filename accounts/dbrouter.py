# DB router for app1

# class DjangoCeleryRouter:
#     """
#     A router to control all database operations on models in the
#     auth application.
#     """
#     def db_for_read(self, model, **hints):
#         """
#         Attempts to read auth models go to auth_db.
#         """
#         if model._meta.app_label == 'django_celery_beat':
#             return 'db_django_celery_beat'
#         return None

#     def db_for_write(self, model, **hints):
#         """
#         Attempts to write auth models go to auth_db.
#         """
#         if model._meta.app_label == 'django_celery_beat':
#             return 'db_django_celery_beat'
#         return None

#     def allow_relation(self, obj1, obj2, **hints):
#         """
#         Allow relations if a model in the auth app is involved.
#         """
#         if obj1._meta.app_label == 'django_celery_beat' or \
#            obj2._meta.app_label == 'django_celery_beat':
#            return True
#         return None

#     def allow_migrate(self, db, app_label, model_name=None, **hints):
#         """
#         Make sure the auth app only appears in the 'db_django_celery_beat'
#         database.
#         """
#         if app_label == 'django_celery_beat':
#             return db == 'db_django_celery_beat'
#         return None


class CheckerRouter:

    def db_for_read(self, model, **hints):
        
        if model._meta.app_label == 'user':
            return 'userdb'
        return 'default'

    def db_for_write(self, model, **hints):
        
        if model._meta.app_label == 'user':
            return 'userdb'
        return 'default'

    def allow_relation(self, obj1, obj2, **hints):
        
        if obj1._meta.app_label == 'user' or obj2._meta.app_label == 'user':
            return True
        if 'user' not in [obj1._meta.app_label, obj2._meta.app_label]:
            return True
        return False

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        
        if app_label == 'user':
            return db == 'userdb'
        return None
