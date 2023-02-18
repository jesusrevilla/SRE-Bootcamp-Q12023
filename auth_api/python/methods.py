# These functions need to be implemented
import pymysql
import hashlib
import jwt

from flask import abort


def hash512_append_salt(password, salt):
    '''
        Hash 512 password appended salt

        :param password - input password
        :param salt - input salt

        :return string - hashed password and salt
    '''
    pass_salt = password + salt
    pass_salt = pass_salt.encode("utf-8")
    return hashlib.sha512(pass_salt).hexdigest()

def encode_ywt(role):
    return jwt.encode(
        {"role":role},
        "my2w7wjd7yXF64FIADfJxNs1oupTGAuW",
        algorithm="HS256"
    )

def decode_jwt(encoded):
    return jwt.decode(
        encoded,
        "my2w7wjd7yXF64FIADfJxNs1oupTGAuW",
        algorithms=["HS256"]
    )

class Token:

    def generate_token(self, username, password):
        # Get username, password, salt and role from database
        db = Database()
        user_data = db.query_user(username)

        # Hash password with salt
        hash512 = hash512_append_salt(password, user_data['salt'])

        # Compare hashed password from database with input
        if hash512 == user_data['password']:
            return encode_ywt(user_data['role'])
        else:
            abort(403, description="Incorrect username or password")


class Restricted:

    def access_data(self, authorization):
        if "." in authorization:
            decoded = decode_jwt(authorization)
        else:
            decoded = {'role': ""}
        if decoded['role'] in ['admin', 'editor', 'viewer']:
            return "You are under protected data"
        else:
            return "Incorrect access token"
    
class Database:

    def __init__(self):
        self.con = pymysql.connect(
            host='sre-bootcamp-selection-challenge.cabf3yhjqvmq.us-east-1.rds.amazonaws.com',
            port=3306,
            user='secret',
            password='jOdznoyH6swQB9sTGdLUeeSrtejWkcw',
            database='bootcamp_tht'             
        )

    def query_user(self, user):
        try:
            with self.con.cursor() as cur:
                cur.execute(f"SELECT * FROM users WHERE users.username = '{user}'")
                user_row = cur.fetchone()
                return {'username': user_row[0],
                        'password': user_row[1],
                        'salt': user_row[2],
                        'role': user_row[3]}

        except pymysql.Error as e:
            print(f"Connection error: {e}")

        finally:
            self.con.close()
