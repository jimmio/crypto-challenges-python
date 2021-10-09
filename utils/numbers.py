from decimal import Decimal, ROUND_UP

def round_up_nearest_int(n):
    rounded = Decimal(n).quantize(Decimal("1."), rounding=ROUND_UP)
    return int(rounded)
