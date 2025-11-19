# import
import numpy as np


# starting values
B = 3
q = 13
A = np.array([[1, 2, 4, 5, 9],
              [3, 1, 2, 8, 12],
              [1, 2, 3, 4, 5]])


# SIS solutions
A_solve = np.array([[1, 0, 0, 11/5, 3 ], # calculated by hand
                    [0, 1, 0, -3/5 ,-5],
                    [0, 0, 1, 1, 4 ]])

a = np.array([[-3],[5],[-4],[0],[1]])
b = 5*np.array([[-11/5],[3/5],[-1],[1],[0]]) # compensated for whole numbers


# make filter go over -q not only positive q
# So you will get negative answers
def centered_mod(arr, q): #AI
    return ((arr + q//2) % q) - q//2


# filter solutions
for n1 in range(q):
    for n2 in range(q):
        z = centered_mod(a*n1 + b*n2, q)
        res = np.dot(A, z) % q
        if sum(res) == 0 and np.all(z <= B) and np.all( z >= -B):
            print("Solution:\n", z, "\n")