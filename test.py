import os

lines = []
assumption_lines = []

with open("scoin.c", "r") as file:
    lines = file.readlines()

with open("ASSUMPTIONS.txt", "r") as file:
    assumption_lines = file.readlines()

lines[182:185] = assumption_lines

with open("scoin.c", "w") as file:
    file.writelines(lines)