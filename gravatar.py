from flask_gravatar import Gravatar
import hashlib


def get_gravatar_url(email, size=200):
    # Convert email to lowercase and create an MD5 hash
    hashed_email = hashlib.md5(email.lower().encode('utf-8')).hexdigest()

    # Construct the Gravatar URL
    gravatar_url = f"https://www.gravatar.com/avatar/{hashed_email}?s={size}"

    return gravatar_url
