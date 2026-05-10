def handle(user_expr: str):
    return eval(user_expr)

print(handle(input("expr> ")))
