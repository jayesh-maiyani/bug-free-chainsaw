from subscription.models import OrganizationPlan
from .models import LogModel, Organization, DeviceLog


def client_log(request, org, action, user = None, actor_id = None):
    id = None
    if actor_id is not None:
        id = actor_id
    else:
        id = request.user.id
    LogModel.objects.create(
        actor_type = "CL",
        actor_id = id,
        org = org, 
        action = action,
        user = user
    )

# def device_log(device, org, action, user, outcome = None):
#     DeviceLogModel.objects.create(
#         device = device,
#         org = org, 
#         action = action,
#         user = user,
#         outcome = outcome
#     )


def validate_payload(payload, valid_keys):
    data = payload.copy()
    for key in data:
        if key not in valid_keys:
            payload.pop(key)
    return payload



def has_active_subscription(org):
    org_plans = OrganizationPlan.objects.filter(organization = org, is_plan_active = True, subscription_plan__plan_type__in = ['MONTHLY', 'YEARLY', 'CUSTOM', 'DAILY'])
    return org_plans.exists()

def has_active_trial(org):
    org_plans = OrganizationPlan.objects.filter(organization = org, is_plan_active = True, subscription_plan__plan_type__in = ['TRIAL'])
    return org_plans.exists()

def has_active_plan(org):
    return OrganizationPlan.objects.filter(organization = org, is_plan_active = True).exists()

def can_avail_trial(org):
    org_plans = OrganizationPlan.objects.filter(organization = org)
    return not org_plans.exists()

def is_current_plan_paused(org):
    plan = OrganizationPlan.objects.filter(organization = org, is_plan_active = True).first()
    return plan.is_paused
    

def convert_size(size):
    # Define the units and their respective suffixes
    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']
    
    # Initialize the unit index and the divisor
    unit_index = 0
    divisor = 1024
    
    # Iterate until the size is smaller than the divisor or there are no more units
    while size >= divisor and unit_index < len(units)-1:
        size /= divisor
        unit_index += 1
    
    # Format the size with two decimal places and the appropriate unit
    formatted_size = "{:.2f} {}".format(size, units[unit_index])
    
    return formatted_size


def bytest_to_kb(value):
    kb = value / 1024
    return round(kb)



import random
import time
    
def str_time_prop(start, end, time_format, prop):
    """Get a time at a proportion of a range of two formatted times.YYYY-MM-DD HH:MM

    start and end should be strings specifying times formatted in the
    given format (strftime-style), giving an interval [start, end].
    prop specifies how a proportion of the interval to be taken after
    start.  The returned time will be in the specified format.
    """

    stime = time.mktime(time.strptime(start, time_format))
    etime = time.mktime(time.strptime(end, time_format))

    ptime = stime + prop * (etime - stime)

    return time.strftime(time_format, time.localtime(ptime))


def random_date(start, end, prop):
    return str_time_prop(start, end, '%Y-%m-%d %I:%M', prop)



def add_logs(service_name):
    organization = Organization.objects.get(id = 35)
    for _ in range(100):
        DeviceLog.objects.create(
            changed_by = "kalpesh@crawlapps.com",
            title = "Manual execution completed",
            sentence = "Manual execution",
            device_id = "258",
            device_serial_no = "5GJLN13",
            service_name = service_name,
            file_deleted = random.randrange(10000, 100000),
            time = random_date("2023-01-01 1:00", "2023-07-01 4:50", random.random()),
            organization = organization,
            current_user = "DELL"
        )



# def device_log(request, org, action, outcome = None, user = None):
#     DeviceLogModel.objects.create(
#         actor_id = request.user.id,
#         org = org, 
#         action = action,
#         user = user,
#         outcome = outcome
#     )


# def service_log(request, sub_service, action, outcome = None, user = None):
#     SubServiceLogModel.objects.create(
#         actor_id = request.user.id,
#         sub_service = sub_service, 
#         action = action,
#         user = user,
#         outcome = outcome
#     )


# def payload_validator(valid_keys, )
