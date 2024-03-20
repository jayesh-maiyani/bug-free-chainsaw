"""
ASGI config for fds_client project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/3.0/howto/deployment/asgi/
"""

import os, django

from django.core.asgi import get_asgi_application

from socketio.asgi import ASGIApp



os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'fds_client.settings')
django.setup()

from accounts.models import User
all_users = User.objects.filter(is_staff = False)
all_users.update(socket_id = list(), is_online = False)


from accounts.socket_app import get_socketio_app
sio = get_socketio_app()

application = get_asgi_application()

app = ASGIApp(
    sio,
    application, 
)



############################################################################################################################################################
# from channels.routing import ProtocolTypeRouter, URLRouter
# from channels.auth import AuthMiddlewareStack

# from django.db.models.signals import post_save
# from django.dispatch import receiver
# from channels.db import database_sync_to_async

# from django.shortcuts import get_object_or_404
# import accounts.models

# import socketio

# from subscription.models import OrganizationPlan

# @database_sync_to_async
# def get_current_user(id):
#     return accounts.models.User.objects.get(id = id)
# # from accounts.serializers import UserSocketSerializer

# @database_sync_to_async
# def get_organization(id):
#     return accounts.models.Organization.objects.get(id = id)

# @database_sync_to_async
# def has_active_plan(org):
#     org_plans = OrganizationPlan.objects.filter(organization = org, is_plan_active = True, subscription_plan__id__in = [2,3,4])
#     if org_plans.exists():
#         return True
#     else:
#         return False

# @database_sync_to_async
# def set_user_online_status(user, status):
#     user.is_online = status
#     user.save()

# @sio.event
# async def connect(sid, environ):
#     all_keys = environ['QUERY_STRING'].split('&')
#     key = all_keys[0].split('=')
#     if key[0] == 'org_id':
#         room = key[1]
#         sio.enter_room(sid, room)
#         await sio.emit('msg', {'text':f"Client {sid} joined room {room}."}, room = room)




# @sio.event
# async def message(sid, data):
#     print('message received with ', data)
#     await sio.emit('chat_message', {'message':'hey client'}, to=sid)


# @sio.event
# async def user_online(sid, data):
#     user = await get_current_user(id = data['user_id'])
#     print('######data_online', data)
#     await set_user_online_status(user, status = True)
#     online_users = {
#         'user_id' : user.id,
#         'is_online' : True
#     }
#     await sio.emit('user_online_status', online_users, room = str(data['org_id']), skip_sid = sid)


# @sio.event
# async def subscription_plan(sid, data):
#     org_id = data['org_id']
#     org = await get_organization(int(org_id))
#     active_plan = await has_active_plan(org)
#     data = {
#         'active_plan' : active_plan
#     }
#     await sio.emit('has_active_plan', data, to = sid)
    

# @sio.event
# async def user_offline(sid, data):
#     user = await get_current_user(id = data['user_id'])
#     print('######data_online', data)
#     await set_user_online_status(user, status = True)
#     online_users = {
#         'user_id' : user.id,
#         'is_online' : False
#     }
#     await sio.emit('user_online_status', online_users, room = str(data['org_id']), skip_sid = sid)


# @sio.event
# async def disconnect(sid):
#     print(f"WebSocket client disconnected: {sid}")
#     sio.disconnect(sid)


# @receiver(post_save, sender = accounts.models.User)
# async def user_update(sender, instance, created, update_fields, **kwargs):
#     try:
#         if not created and instance.is_staff != True:
#             print("##instance", instance)
#             user = instance.id
#             permission = ''
#             if instance.is_owner == True:
#                 permission = "client_owner"
#             elif instance.has_perm("accounts.client_admin"):
#                 permission = "client_admin"
#             elif instance.has_perm("accounts.client_user"):
#                 permission = "client_user"
#             elif instance.has_perm("accounts.client_reader"):
#                 permission = "client_reader"
            

#             org_id = accounts.models.Organization.objects.get(name = instance.org).id
#             data = {
#                 'user_id':user,
#                 'permission':permission,
#             }

#             await sio.emit('user_permission', data, room = str(org_id))
#     except Exception as e:
#         traceback.print_stack()
#         print("error", str(e))





# application = ProtocolTypeRouter({
#     'http':get_asgi_application(),
#     'websocket':AuthMiddlewareStack(
#         URLRouter(
#             accounts.routing.websocket_urlpatterns
#         )
#     )
# })

# class OrganizationNamespace(socketio.AsyncNamespace):
#     async def on_connect(self, sid, environ):
#         # Get the name of the organization from the query parameters
#         org_name = environ['QUERY_STRING'].split('=')[1]
#         # Get the organization object
#         org = get_object_or_404(accounts.models.Organization, name = org_name)
#         # Join the organization room
#         await sio.enter_room(sid, f"org_{org.id}")

#     async def on_disconnect(self, sid):
#         # Leave all rooms when a user disconnects
#         rooms = sio.rooms(sid)
#         for room in rooms:
#             await sio.leave_room(sid, room)

#     async def on_send_message(self, sid, message):
#         # Get the organization room for the user
#         rooms = sio.rooms(sid)
#         for room in rooms:
#             if room.startswith('org_'):
#                 org_room = room
#                 break
#         # Emit the message to all users in the organization room
#         await sio.emit('receive_message', message, room=org_room)

# @sio.on('connect')
# async def connect(sid, environ):
#     print('#####connected')
#     await sio.emit('connection', 'hi client', to=sid)

# @sio.on('chat')
# async def chat(sid, environ):
#     print("##environ:", environ)

    # Extract org_id from query params
    # org_id = environ['QUERY_STRING'].split('=')[1]

    # # Join room based on org_id
    # await sio.enter_room(sid, f'org_{org_id}')


# @sio.on('')
# def join_org_room(sid, data):
#     org_id = data.get('org_id', '1')
#     print(org_id)
#     sio.enter_room(sid, f"org_{org_id}")
#     print('joined_room:', f"org_{org_id}")

# @sio.event
# def message(sid, data):
#     sio.emit('message', "Hi guys")

# @sio.on('message')
# async def message(sid, data):
#     session = await sio.get_session(sid)
#     print('message from ', session['username'])

