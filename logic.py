import math
import re


def get_personal_info_warnings(password):
    warnings = []
    phone_pattern = r'^05\d[- ]?\d{7}$|^\d{10}$'
    id_pattern = r'^\d{9}$'

    if re.match(phone_pattern, password):
        warnings.append("Warning: This may looks like a phone number. Hackers can easily find this via social engineering.")

    if re.match(id_pattern, password) and not re.match(phone_pattern, password):
        warnings.append(
            "Warning: This my looks like an ID number. Personal identifiers are highly vulnerable to targeted attacks.")

    if re.search(r'(\d)\1{4,}', password):
        warnings.append("Warning: Avoid using long sequences of the same character.")

    return warnings


def analyze_password(password):
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    pool_size = 0
    if has_lower: pool_size += 26
    if has_upper: pool_size += 26
    if has_digit: pool_size += 10
    if has_special: pool_size += 32

    length = len(password)
    if length == 0:
        return {"score": 0, "human_time": "0 seconds", "warnings": []}

    combinations = pool_size ** length
    guesses_per_second = 10 ** 10
    seconds = combinations / guesses_per_second

    personal_warnings = get_personal_info_warnings(password)

    return {
        "score": calculate_score(length, pool_size),
        "seconds": seconds,
        "human_time": format_time(seconds),
        "warnings": personal_warnings
    }


def calculate_score(length, pool):
    if length < 6: return 1
    if length >= 12 and pool > 60: return 5
    if length >= 8 and pool > 30: return 3
    return 2


def format_time(seconds):
    if seconds < 1:
        return "Instantly"

    units = [
        (31536000, "years"),
        (86400, "days"),
        (3600, "hours"),
        (60, "minutes"),
        (1, "seconds")
    ]

    century = 100 * 31536000
    if seconds > century:
        return "Centuries (Unbreakable)"

    for limit, name in units:
        if seconds >= limit:
            value = int(seconds / limit)
            return f"{value} {name}"


    return "Instantly"

    return "Instantly"
