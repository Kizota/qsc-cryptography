for n in (2514,1125,333,3696,2514,2929,3368,2514):
    for n2 in range(128):
        if (n2**11)%3763 == n:
            #print(f"({n2}**11) mod {n}")
            print(chr(n2))