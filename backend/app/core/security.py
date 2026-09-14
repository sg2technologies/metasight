from passlib.context import CryptContext

# Argon2id: OWASP recommended, memory-hard, no password length limit.
# Falls back to any deprecated scheme automatically on verify.
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)
