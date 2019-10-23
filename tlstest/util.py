def print_if(a, b):
    if a:
        return a
    return b


def yn(test):
    return 'yes' if test else 'no'


def eq_yn(test, test2):
    return 'yes' if test == test2 else 'no'
