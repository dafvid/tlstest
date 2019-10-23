import sys


def print_if(a, b):
    if a:
        return a
    return b


def yn(test):
    return 'yes' if test else 'no'


def eq_yn(test, test2):
    return 'yes' if test == test2 else 'no'


def parse_args(args, pop=True):
    arg_list = [arg for arg in sys.argv][1:]
    r = dict()
    for a in args:
        if a in arg_list:
            idx = arg_list.index(a) + 1
            if idx < len(arg_list):
                v = arg_list[idx]
                r[a] = v
                if pop:
                    sys.argv.remove(v)
                    sys.argv.remove(a)
        else:
            r[a] = ''

    return r


def parse_flargs(args, pop=True):
    arg_list = [arg.lower() for arg in sys.argv][1:]
    r = dict()
    for a in args:
        v = a in arg_list
        r[a] = v
        if v and pop:
            sys.argv.remove(a)

    return r
