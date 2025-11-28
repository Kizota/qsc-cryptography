#import numpy as np
#from fractions import Fraction
from Schoolbook_method import mul_school_c
from Karatsuba_s_method import mul_karatsuba_c
from Toom3 import toom3_mul_c
from Toom3_school import mul_toom3_school_c
from NTT import mul_NTT_c

# all examples
print('\n\n\n')
print('schoolbook:',mul_school_c([6, 10, 3, 12], [5, 2, 7, 9]))
print('karatsuba:',mul_karatsuba_c([6, 10, 3, 12], [5, 2, 7, 9]))
print('toom3:',toom3_mul_c([6, 10, 3, 12], [5, 2, 7, 9]))
print('toom3+schoolbook:',mul_toom3_school_c([6, 10, 3, 12], [5, 2, 7, 9]))
print('toom3+schoolbook with reduced threshold:',mul_toom3_school_c([6, 10, 3, 12], [5, 2, 7, 9],3))
print('NTT:',mul_NTT_c([6, 10, 3, 12], [5, 2, 7, 9]))
