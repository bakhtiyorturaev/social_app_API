import random
code = ''.join(str(random.randint(0, 100) % 10) for _ in range(4))
print(code)