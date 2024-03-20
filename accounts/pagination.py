import math
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response

class StandardResultsSetPagination(PageNumberPagination):
    page_size = 8
    page_size_query_param = 'page_size'
    max_page_size = 100

    def get_paginated_response(self, data, total_counts = None, subscription_flag = None, no_of_devices = None):
        page_counts = math.ceil(self.page.paginator.count / self.page_size)
        # current_page = self.get_page_number()
        
        return Response({
            'links': {
                'next': self.get_next_link(),
                'previous': self.get_previous_link()
            },
            'count': self.page.paginator.count,
            'results': data,
            'total_counts': total_counts,
            'subscription_flag': subscription_flag,
            'total_page': page_counts,
            'current_page': self.page.number,
            'no_of_devices': no_of_devices
    })


class MobilePagination(PageNumberPagination):
    page_size = 5000

    def get_paginated_response(self, data, total_counts = None, subscription_flag = None):
        page_counts = math.ceil(self.page.paginator.count / self.page_size)
        return Response({
            'links': {
                'next': self.get_next_link(),
                'previous': self.get_previous_link()
            },
            'count': self.page.paginator.count,
            'results': data,
            'total_counts': total_counts,
            'total_page': page_counts,
            'current_page': self.page.number,
            'subscription_flag':subscription_flag
    })
