from itertools import chain
from os import urandom
from random import randint

def is_list(thing):
    return type(thing) == "list"

def partition_all(lst, size):
    if not lst: return ()
    return [lst[i:i+size] for i in range(0, len(lst), size)]

def transpose(lsts):
    len_fst_itm = len(lsts[0])
    range_of_itms = range(0, len_fst_itm)
    return [[lst[i] for lst in lsts if (len(lst) == len_fst_itm)] for i in range_of_itms]

def flatten(lsts):
    return list(chain(*lsts))

def append_rand_bytes(byte_list):
    pre_r, post_r = randint(5,10), randint(5,10)
    pre, post = urandom(pre_r), urandom(post_r)
    pre_ints, post_ints = [b for b in pre], [b for b in post]
    return flatten([pre_ints, byte_list, post_ints])

def all_same(lst):
    return len(set(lst)) == 1

def index_duplicate(lst):
    enumd = enumerate(lst)
    return [(n, item) for (n, item) in enumd if item in lst[n+1:]]

def tablify_bytes(byte_list):
    return ['{:3d}'.format(b) for b in byte_list]

def shortest(lsts):
    w_lens = [(len(el), el) for el in lsts]
    return sorted(w_lens)[0][1]
