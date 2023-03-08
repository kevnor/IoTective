def subnet_to_cidr(subnet_mask):
    """
    Converts a subnet mask to CIDR notation.

    Args:
    subnet_mask (str): Subnet mask in dotted decimal notation (e.g. "255.255.255.0")

    Returns:
    int: CIDR notation (e.g. 24 for subnet mask "255.255.255.0")
    """
    # Convert subnet mask to binary string
    binary_mask = ''.join([bin(int(x))[2:].zfill(8) for x in subnet_mask.split('.')])

    # Count the number of consecutive ones in the binary string
    cidr = 0
    for i in range(len(binary_mask)):
        if binary_mask[i] == '1':
            cidr += 1
        else:
            break

    return cidr


def search_nested_dict(nested_dict, search_key):
    """
    Searches a nested dictionary for a key and returns its value if it exists.

    Args:
    nested_dict (dict): The nested dictionary to search.
    search_key (str): The key to search for.

    Returns:
    The value of the key if it exists, or None if it does not.
    """
    # Check if the search key is in the top-level dictionary
    if search_key in nested_dict:
        return nested_dict[search_key]

    # Recursively search sub-dictionaries
    for key, value in nested_dict.items():
        if isinstance(value, dict):
            result = search_nested_dict(value, search_key)
            if result is not None:
                return result

    # Key not found
    return None
