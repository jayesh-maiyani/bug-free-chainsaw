from datetime import datetime
from channels.db import database_sync_to_async
from django.conf import settings
import accounts.models

import socketio, asyncio

from subscription.models import OrganizationPlan


@database_sync_to_async
def get_current_user(id):
    return accounts.models.User.objects.get(id = id)


@database_sync_to_async
def get_organization(id):
    try:
        return accounts.models.Organization.objects.get(id = id)
    except:
        return None

@database_sync_to_async
def get_user_org_id(user):
    return accounts.models.Organization.objects.get(user = user).id

@database_sync_to_async
def get_user_from_sid(sid):
    user_qs = accounts.models.User.objects.filter(socket_id__contains = [sid])
    if user_qs.exists():
        return user_qs.first()
    return None

@database_sync_to_async
def set_user_offline(user, sid):
    if len(user.socket_id) == 1:
        user.is_online = False
        user.last_online_time = datetime.now()
    user.socket_id.remove(sid)
    user.save()

@database_sync_to_async
def get_online_counts(user):
    return len(user.socket_id)


@database_sync_to_async
def get_registered_devices(org):
    return accounts.models.Device.objects.filter(org = org, soft_delete = False).count()


@database_sync_to_async
def has_active_plan(org):
    org_plans = OrganizationPlan.objects.filter(organization = org, is_plan_active = True, subscription_plan__plan_type__in = ['MONTHLY', 'YEARLY', 'CUSTOM', 'DAILY'])
    return org_plans.exists()


@database_sync_to_async
def get_active_plan(org):
    org_plans = OrganizationPlan.objects.filter(organization = org, is_plan_active = True)
    if org_plans.exists():
        return org_plans.first()
    else:
        return None

@database_sync_to_async
def can_avail_trial(org):
    org_plans = OrganizationPlan.objects.filter(organization = org)
    return not org_plans.exists()


@database_sync_to_async
def has_expired_plan(org):
    org_plans = OrganizationPlan.objects.filter(organization = org)
    expired = True
    if org_plans.exists():
        subscriptions = org_plans.filter(is_plan_active = True)
        if subscriptions.exists():
            expired = False
    return expired

@database_sync_to_async
def set_user_online_status(user, status, sid):
    user.is_online = status
    user.socket_id.append(sid)
    user.last_online_time = datetime.now()
    user.save()

@database_sync_to_async
def get_user_permissions(user):
    permissions = user.user_permissions.all()
    for permission in permissions:
        return permission.codename



############################################################################################################################################################################################################

sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins=settings.CORS_ORIGIN_WHITELIST, logger = True, engineio_logger = True)


@sio.event
async def connect(sid, environ):
    try:
        all_keys = environ['QUERY_STRING'].split('&')
        key = all_keys[0].split('org_id=')
        user_id = all_keys[1].split("user_id=")
        room = key[1]
        if user_id[1].isnumeric():
            user = await get_current_user(id = user_id[1])
            await set_user_online_status(user, status = True, sid = sid)
            if room.isnumeric():
                sio.enter_room(sid, room)
                org = await get_organization(int(room))
                if org is not None:
                    online_users = {
                        'user_id' : user.id,
                        'is_online' : True
                    }
                    await sio.emit('user_online_status', online_users, room = room)
                    print(f"sending online status of user {user.id} in room {room}")
                    trial_plan = await can_avail_trial(org)
                    trial_data = {
                        'can_get_trail' : trial_plan
                    }
                    await sio.emit('can_avail_trial', trial_data, sid)

                    expired_plan = await has_expired_plan(org)
                    expired_data = {
                        'is_plan_expired' : expired_plan
                    }
                    await sio.emit('has_plan_expired', expired_data, sid)
                    plan = await get_active_plan(org)
                    plan_data = {
                        'device_limit' : plan.device_limit if plan is not None else 0,
                        'utilized_limit': plan.utilized_limit if plan is not None else 0,
                        'registered_devices': await get_registered_devices(org)
                    }
                    await sio.emit('plan_limits', plan_data, to = sid)
    except Exception as e:
        print(str(e))



@sio.event
async def get_user_permission(sid, data):
    if isinstance(data, dict):
        if isinstance(data['user_id'], int) or isinstance(data['user_id'], str):
            user = await get_current_user(id = data['user_id'])
            permission = await get_user_permissions(user)
            if permission == "client_admin" and user.is_owner:
                permission = "client_owner"
            permission_data = {
                'user_id':user.id,
                'permission':permission,
            }
            await sio.emit('user_permission', permission_data, room = str(data['org_id']))



@sio.event
async def subscription_plan(sid, data):
    org_id = data['org_id']
    org = await get_organization(int(org_id))
    active_plan = await has_active_plan(org)
    data = {
        'active_plan' : active_plan
    }
    await sio.emit('has_active_plan', data, to = sid)


@sio.event
async def can_have_trial(sid, data):
    org_id = data['org_id']
    org = await get_organization(int(org_id))
    trial_plan = await can_avail_trial(org) #bool
    data = {
        'can_get_trail' : trial_plan
    }
    await sio.emit('can_avail_trial', data, to = sid)
    

@sio.event
async def user_offline(sid, data):
    user = await get_current_user(id = data['user_id'])
    await set_user_online_status(user, status = False, sid = sid)
    online_users = {
        'user_id' : user.id,
        'is_online' : False
    }
    await sio.emit('user_online_status', online_users, room = str(data['org_id']), skip_sid = sid)


@sio.event
async def get_plan_limits(sid, data):
    org_id = data['org_id']
    org = await get_organization(int(org_id))
    plan = await get_active_plan(org)
    plan_data = {
        'device_limit' : plan.device_limit if plan is not None else 0,
        'utilized_limit': plan.utilized_limit if plan is not None else 0,
        'registered_devices': await get_registered_devices(org)
    }
    await sio.emit('plan_limits', plan_data, to = sid)


async def check_client_alive(sid):
    while True:
        await asyncio.sleep(10)  # Adjust this interval as needed
        user = await get_user_from_sid(sid)
        if user is not None:
            return
        try:
            await sio.emit('ping', sid = sid)
        except Exception as e:
            print(f"Client {sid} is not responding. Disconnecting...")
            await sio.disconnect(sid)
            return

@sio.event
async def disconnect(sid):
    user = await get_user_from_sid(sid)
    if user is not None:
        await set_user_offline(user, sid)
        if await get_online_counts(user) == 0:
            org = await get_user_org_id(user)
            online_users = {
                'user_id' : user.id,
                'is_online' : False
            }
            await sio.emit('user_online_status', online_users, room = str(org))
            print(f"sending offline status of user {user.id} in room {org}")
    await sio.disconnect(sid)



def get_socketio_app():
    return sio


