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
    formatted_size = "{:.2f} {} {}".format(size, units[unit_index], 'cleared')
    
    return formatted_size
