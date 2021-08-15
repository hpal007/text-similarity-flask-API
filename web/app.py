from flask import Flask, json, request, jsonify
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import spacy


# App initialisation
app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.SentencesDatabase
users = db["Users"]


def user_exist(name):
    if users.find({"Username": name}).count() == 0:
        return True
    else:
        return False


def verify_pw(username, password):
    hashed_pw = users.find({"Username": username})[0]["Password"]
    if bcrypt.checkpw(password.encode('utf8'), hashed_pw):
        return True
    else:
        return False


def get_token_count(username):

    token = users.find({"Username": username})[0]["Token"]
    return token


class Register(Resource):
    def post(self):

        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]

        if not user_exist(username):
            retJson = {
                "status": 301,
                "msg": f"Username {username} already exist, please use other username."}
            return retJson

        hash_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        users.insert_one({
            "Username": username,
            "Password": hash_pw,
            "Token": 5})

        retJson = {
            "status": 200,
            "msg": "You successfully signed up for the API"
        }
        return jsonify(retJson)


class Detect(Resource):
    def post(self):

        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]
        text1 = postedData["text1"]
        text2 = postedData["text2"]

        if user_exist(username):
            retJson = {
                "status": 301,
                "msg": f"Username {username} does not exist, pls register."}
            return retJson

        if not verify_pw(username, password):
            retJson = {
                "status": 302,
                "msg": f"Invalid password for username {username}, please re-check your password."}
            return retJson

        no_of_token = get_token_count(username)
        if no_of_token == 0:
            returnJson = {
                "status_code": 304,
                "msg": "You are out of token, use refill."
            }
            return jsonify(returnJson)

        nlp = spacy.load("en_core_web_sm")

        text1 = nlp(text1)
        text2 = nlp(text2)

        similarity = text1.similarity(text2) *100

        retJson = {
            "status": 200,
            "similarity": similarity,
            "msg": "Similarity score calculated successfully"
        }

        users.update({"Username": username}, {
                     "$set": {"Token": no_of_token-1}})
        return jsonify(retJson)


class Refill(Resource):
    def post(self):

        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]
        refill_amount  = postedData["refill"]


        if user_exist(username):
            retJson = {
                "status": 301,
                "msg": f"Username {username} does not exists, pls create one. "}
            return retJson

        if not verify_pw(username, password):
            retJson = {
                "status": 304,
                "msg": f"Invalid password for username {username}, please re-check your password."}
            return retJson

        no_of_token = get_token_count(username)
        users.update({"Username": username}, {
                     "$set": {"Token": no_of_token + refill_amount}})

        
        retJson = {
            "status": 200,
            "msg": "Refill successfully"
        }

        return jsonify(retJson)


api.add_resource(Register,'/register')
api.add_resource(Detect,'/detect')
api.add_resource(Refill,'/refill')


@app.route('/')
def hello_world():
    desc_str = '''Wellcome on similarity check server !!!  
                    Use /register to register new user 
                    Use /detect to check for similarity 
                    Use /refill to add mroe tokens for regieterd users.'''

    return desc_str
if __name__== "__main__":
    app.run(host="0.0.0.0")


