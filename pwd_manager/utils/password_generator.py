import random
import string

def generate_password():
    """Generate a password with 3-5 groups of 4-6 alphanumeric characters joined by hyphens"""
    def generate_group():
        # Define character set: lowercase, uppercase, and numbers
        chars = string.ascii_letters + string.digits
        # Random length between 4 and 6
        length = random.randint(4, 6)
        return ''.join(random.choice(chars) for _ in range(length))
    
    # Generate between 3 to 5 groups
    num_groups = random.randint(3, 5)
    # Generate groups and join them with hyphens
    return '-'.join(generate_group() for _ in range(num_groups))
