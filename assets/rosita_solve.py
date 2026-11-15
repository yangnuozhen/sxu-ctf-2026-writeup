"""Solve Rosita using an anomalous-curve map and an orthogonal lattice.

Dependencies: pip install sympy fpylll cysignals python-flint
Usage: python rosita_solve.py [2023dfjk02.zip]
"""

import ast
import math
import sys
import zipfile
from pathlib import Path

local_dependencies = Path(__file__).parent / '.deps' / 'rosita'
if local_dependencies.is_dir():
    sys.path.insert(0, str(local_dependencies))

from flint import fmpz_mat
from fpylll import IntegerMatrix, LLL
from sympy import factorint, isprime


def recover_curve(points):
    x0, y0 = points[0]
    x1, y1 = points[1]
    t0, t1 = y0*y0 - x0**3, y1*y1 - x1**3
    common = 0
    for x, y in points[2:]:
        determinant = (y*y - x**3 - t0)*(x1 - x0) - (t1 - t0)*(x - x0)
        common = math.gcd(common, determinant)
    # For this attachment the common divisor is 4*p.
    p = max(factorint(common, limit=10000))
    assert isprime(p)
    a = (t1 - t0)*pow(x1 - x0, -1, p) % p
    b = (t0 - a*x0) % p
    assert all((y*y - x**3 - a*x - b) % p == 0 for x, y in points)
    assert (4*a**3 + 27*b*b) % p != 0
    return int(p), int(a), int(b)


class Curve:
    """Jacobian arithmetic over F_p and Z/(p^2), without SageMath."""

    def __init__(self, p, a, b):
        self.p, self.a, self.b = p, a, b

    def double(self, P, modulus):
        X, Y, Z = P
        S = 4*X*Y*Y % modulus
        M = (3*X*X + self.a*pow(Z, 4, modulus)) % modulus
        T = (M*M - 2*S) % modulus
        return (T, (M*(S - T) - 8*pow(Y, 4, modulus)) % modulus,
                2*Y*Z % modulus)

    def add(self, P, Q, modulus):
        X, Y, Z = P
        x, y, z = Q
        if Z == 0:
            return Q
        if z == 0:
            return P
        U, u = X*z*z % modulus, x*Z*Z % modulus
        S, s = Y*pow(z, 3, modulus) % modulus, y*pow(Z, 3, modulus) % modulus
        H, R = (u - U) % modulus, (s - S) % modulus
        if H == 0:
            return self.double(P, modulus) if R == 0 else (1, 1, 0)
        h2 = H*H % modulus
        h3 = H*h2 % modulus
        T = (R*R - h3 - 2*U*h2) % modulus
        return T, (R*(U*h2 - T) - S*h3) % modulus, H*Z*z % modulus

    def mul(self, k, P, modulus):
        result = (1, 1, 0)
        while k:
            if k & 1:
                result = self.add(result, P, modulus)
            P = self.double(P, modulus)
            k >>= 1
        return result

    def logarithm(self, P):
        # Lift P to the curve modulo p^2 using one Hensel step.
        p = self.p
        x, y = P
        correction = ((x**3 + self.a*x + self.b - y*y)//p)*pow(2*y, -1, p) % p
        X, Y, Z = self.mul(p, (x, y + p*correction, 1), p*p)
        assert Z % p == 0 and Y % p != 0
        # Formal-group parameter -x/y = -X*Z/Y, divided by p.
        return -X*(Z//p)*pow(Y, -1, p) % p

    def affine(self, P):
        X, Y, Z = P
        return X*pow(Z, -2, self.p) % self.p, Y*pow(Z, -3, self.p) % self.p


def recover_hidden_vectors(logs, p):
    n = len(logs)
    # Every row of B is orthogonal to logs modulo p.
    B = IntegerMatrix(n, n)
    B[0, 0] = p
    inverse = pow(logs[0], -1, p)
    for i in range(1, n):
        B[i, 0] = -logs[i]*inverse % p
        B[i, i] = 1
    LLL.reduction(B, delta=0.99)
    short = [[int(B[i, j]) for j in range(n)] for i in range(n - 3)]
    assert max(abs(v).bit_length() for row in short for v in row) <= 8
    assert all(sum(x*y for x, y in zip(row, logs)) % p == 0 for row in short)

    # HNF's unimodular transformation gives the saturated integer kernel.
    H, T = fmpz_mat(short).transpose().hnf(transform=True)
    assert all(H[i, j] == 0 for i in range(n - 3, n) for j in range(n - 3))
    kernel = [[int(T[i, j]) for j in range(n)] for i in range(n - 3, n)]
    K = IntegerMatrix.from_matrix(kernel)
    LLL.reduction(K, delta=0.99)
    return [[int(K[i, j]) for j in range(n)] for i in range(3)]


def solve_coefficients(vectors, logs, p):
    matrix = [[vectors[j][i] for j in range(3)] + [logs[i]] for i in range(3)]
    for col in range(3):
        pivot = next(i for i in range(col, 3) if matrix[i][col] % p)
        matrix[col], matrix[pivot] = matrix[pivot], matrix[col]
        inverse = pow(matrix[col][col], -1, p)
        matrix[col] = [v*inverse % p for v in matrix[col]]
        for row in range(3):
            if row != col:
                scale = matrix[row][col]
                matrix[row] = [(x - scale*y) % p
                               for x, y in zip(matrix[row], matrix[col])]
    return [matrix[i][3] for i in range(3)]


def main():
    archive = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name('2023dfjk02.zip')
    with zipfile.ZipFile(archive) as z:
        points = ast.literal_eval(z.read('out.tuo').decode())
    p, a, b = recover_curve(points)
    curve = Curve(p, a, b)
    print(f'Recovered {p.bit_length()}-bit p, a, b from {len(points)} points.')
    assert curve.mul(p, (*points[0], 1), p)[2] == 0
    # p is prime and lies in the Hasse interval: this proves #E(F_p) = p.
    logs = [curve.logarithm(P) for P in points]
    assert logs[0] != 0
    vectors = recover_hidden_vectors(logs, p)
    print('Hidden vector bit lengths:', [max(map(abs, row)).bit_length() for row in vectors])

    # Recover v_i = 256*r_i + character_i, allowing the LLL sign ambiguity.
    for sign in (1, -1):
        v = [sign*x for x in vectors[0]]
        plaintext = bytes(x % 256 for x in v)
        if all(0 <= x < 2**72 for x in v) and all(32 <= c <= 126 for c in plaintext):
            break
    else:
        raise ValueError('No valid plaintext found in the shortest vector')

    # Validate all scalar equations and all original elliptic-curve points.
    coefficients = solve_coefficients(vectors, logs, p)
    for i, point in enumerate(points):
        predicted = sum(coefficients[j]*vectors[j][i] for j in range(3)) % p
        assert predicted == logs[i]
        scalar = predicted*pow(logs[0], -1, p) % p
        assert curve.affine(curve.mul(scalar, (*points[0], 1), p)) == point
    print(f'Verified all {len(points)} scalar equations and original ECC points.')
    print(plaintext.decode())


if __name__ == '__main__':
    main()
