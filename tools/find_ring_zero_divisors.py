from itertools import combinations, product

Q = 12289
N = 8


def mul(left, right):
    result = [0] * N
    for i, x in enumerate(left):
        for j, y in enumerate(right):
            index = i + j
            if index < N:
                result[index] = (result[index] + x * y) % Q
            else:
                result[index - N] = (result[index - N] - x * y) % Q
    return tuple(result)


values = []
for position in range(N - 1):
    for first, last in product((-1, 1), repeat=2):
        value = [0] * N
        value[position] = first
        value[N - 1] = last
        values.append(tuple(value))

for first, second, third in combinations(values, 3):
    delta01 = tuple((a - b) % Q for a, b in zip(first, second))
    delta02 = tuple((a - b) % Q for a, b in zip(first, third))
    delta12 = tuple((a - b) % Q for a, b in zip(second, third))
    if mul(mul(delta01, delta02), delta12) == (0,) * N:
        print("found", first, second, third, delta01, delta02, delta12)
        break
else:
    print("none", len(values))
