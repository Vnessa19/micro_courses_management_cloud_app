from flask import Flask, request, jsonify, send_file, Response
from google.cloud import datastore, storage
from google.cloud.datastore import query

import requests
import json
import os
import io

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth
from io import BytesIO

PHOTO_BUCKET = 'a6_motali'

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()
USERS = "users"
COURSES = "courses"

ERROR_INVALID_MESSAGE = ({"Error": "The request body is invalid"}, 400)
ERROR_UNAUTHORIZED_MESSAGE = ({"Error": "Unauthorized"}, 401)
ERROR_PERMISSION_MESSAGE = ({"Error": "You don't have permission on this resource"}, 403)
ERROR_NOT_FOUND_MESSAGE = ({"Error": "Not found"}, 404)

# Update the values of the following 3 variables
CLIENT_ID = 'tgwSUbmiN1HsqRNcTr3sZ5wVS4xGE4ER'
CLIENT_SECRET = os.environ.get("AUTH0_CLIENT_SECRET")
DOMAIN = 'dev-4rugwp0wj8ra1j1g.us.auth0.com'
ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


@app.route('/')
def index():
    return "Please navigate to /users to use this API"\

 # 2 Get all users: used only by admin
@app.route('/users', methods=['GET'])
def get_all_users():
        
    # Validate the jwt
    try:
        payload = verify_jwt(request)
    except AuthError:
        return  ERROR_UNAUTHORIZED_MESSAGE

    user_sub = payload['sub']

    query = client.query(kind=USERS)

    # Check if user if admin
    query.add_filter("sub", "=", user_sub)
    query_result = list(query.fetch())
    print("query_result:", query_result)

    # Return error if there is no such user
    if len(query_result) == 0:
        return ERROR_PERMISSION_MESSAGE
    
    # Return error if requester is not admin
    requester = query_result[0]
    if requester["role"] != "admin":
        return ERROR_PERMISSION_MESSAGE
    
    # Return all users
    query = client.query(kind=USERS)
    result = list(query.fetch())
    users = []
    for user in result:
        id = user.key.id
        response = {
            "id" : id,
            "role" : user["role"],
            "sub": user["sub"]
        }
        users.append(response)
    return (users, 200)

# 3 Get a user: used with admin role. Or when JWT is owned by user_id in the path parameter.
@app.route('/' + USERS + '/<int:user_id>', methods=['GET'])
def get_user(user_id):
    
    # Validate the jwt
    try:
        payload = verify_jwt(request)
    except AuthError:
        return  ERROR_UNAUTHORIZED_MESSAGE
    
    user_sub = payload["sub"]
    target_user_key = client.key(USERS, user_id)
    target_user = client.get(target_user_key)

    if target_user is None:
        return ERROR_PERMISSION_MESSAGE
    
    # Find out who own the JWT
    query = client.query(kind=USERS)
    query.add_filter("sub", "=", user_sub)
    jwt_owners = list(query.fetch())
    jwt_owner = jwt_owners[0]

    # Find out if the JWT owner is admin
    if jwt_owner["role"] == "admin":
        response = dict(target_user)
        response["id"] = target_user.key.id
        return response, 200
    # Find out if the JWT owner is student and target_user itself
    elif jwt_owner.key.id == user_id:
        courses = []

        # if the user is instructor, check if they teach any course and add courses 
        if target_user["role"] == "instructor":
            query = client.query(kind=COURSES)
            query.add_filter("instructor_id", "=", user_id)

            for course in query.fetch():
                courses.append(request.host_url + "courses/" + str(course.key.id))

        # if the user is student, check if they enroll any course and add courses
        if target_user["role"] == "student":
            query = client.query(kind=COURSES)

            for course in query.fetch():
                print(course)
                if "students" in course and user_id in course["students"]:
                    courses.append(request.host_url + "courses/" + str(course.key.id))

        response = dict(target_user)
        response.pop("avatar", None)
        response["id"] = target_user.key.id
        response["courses"] = courses
        if "avatar" in target_user:
            response["avatar_url"] = request.host_url + "users/" + str(user_id) + "/avatar"
        return response, 200
    else:
        return ERROR_PERMISSION_MESSAGE

# 4 Create/update a user’s avatar
@app.route('/users/<int:user_id>/avatar', methods=['POST'])
def store_avatar(user_id):

    # Validate the jwt
    try:
        payload = verify_jwt(request)
    except AuthError:
        return  ERROR_UNAUTHORIZED_MESSAGE
    
    # Check if jwt belong to target_user
    target_user_key = client.key(USERS, user_id)
    target_user = client.get(target_user_key)

    if payload["sub"] != target_user["sub"]:
        return ERROR_PERMISSION_MESSAGE
    
    # Any files in the request will be available in request.files object
    # Check if there is an entry in request.files with the key 'file'
    if 'file' not in request.files:
        return ERROR_INVALID_MESSAGE
    
    # Set file_obj to the file sent in the request
    file_obj = request.files['file']
    # If the multipart form data has a part with name 'tag', set the
    # value of the variable 'tag' to the value of 'tag' in the request.
    # Note we are not doing anything with the variable 'tag' in this
    # example, however this illustrates how we can extract data from the
    # multipart form data in addition to the files.
    if 'tag' in request.form:
        tag = request.form['tag']
    # Create a storage client
    storage_client = storage.Client()
    # Get a handle on the bucket
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    # Create a blob object for the bucket with the name of the file
    blob = bucket.blob(file_obj.filename)
    # Position the file_obj to its beginning
    file_obj.seek(0)
    # Upload the file into Cloud Storage
    blob.upload_from_file(file_obj, content_type="image/png")

    # Associate avatar with target_user
    target_user["avatar"] = file_obj.filename
    client.put(target_user)

    avatar_url = request.host_url + "users/" + str(user_id) + "/avatar"

    return {"avatar_url" :avatar_url}, 200

# 5 Get a user’s avatar
@app.route('/users/<int:user_id>/avatar', methods=['GET'])
def get_avatar(user_id):

    # Validate the jwt
    try:
        payload = verify_jwt(request)
    except AuthError:
        return  ERROR_UNAUTHORIZED_MESSAGE
    
    # Check if jwt belong to target_user
    target_user_key = client.key(USERS, user_id)
    target_user = client.get(target_user_key)

    if payload["sub"] != target_user["sub"]:
        return ERROR_PERMISSION_MESSAGE
    
    # Check if target_user has an avatar
    if "avatar" not in target_user:
        return ERROR_NOT_FOUND_MESSAGE
    
    # Retreive avatar image from google storeage
    avatar = target_user["avatar"]
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    # Create a blob with the given file name
    blob = bucket.blob(avatar)
    # Create a file object in memory using Python io package
    avatar_obj = io.BytesIO()
    # Download the file from Cloud Storage to the file_obj variable
    blob.download_to_file(avatar_obj)
    # Position the file_obj to its beginning
    avatar_obj.seek(0)

    # Send the object as a file in the response with the correct MIME type and file name
    return Response(avatar_obj, mimetype='image/png', headers={
        "Content-Disposition": "inline; filename=avatar.png"
        })

# 6.Delete a user’s avatar
@app.route('/users/<int:user_id>/avatar', methods=['DELETE'])
def delete_image(user_id):

    # Validate the jwt
    try:
        payload = verify_jwt(request)
    except AuthError:
        return  ERROR_UNAUTHORIZED_MESSAGE
    
    # Check if jwt belong to target_user
    target_user_key = client.key(USERS, user_id)
    target_user = client.get(target_user_key)

    if payload["sub"] != target_user["sub"]:
        return ERROR_PERMISSION_MESSAGE
    
    # Check if target_user has an avatar
    if "avatar" not in target_user:
        return ERROR_NOT_FOUND_MESSAGE
    
    avatar = target_user["avatar"]
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    blob = bucket.blob(avatar)
    # Delete the file from Cloud Storage
    if blob.exists():
        blob.delete()
    
    # Delete avatar attribute and save on datastore
    del target_user["avatar"]
    client.put(target_user)

    return '',204

 # 7 Create a course: used only by admin
@app.route('/courses', methods=['POST'])
def create_a_course():
    content = request.get_json()
 
    # Validate required_attributes
    required_attributes = ["subject", "number", "title", "term", "instructor_id"]
    for attribute in required_attributes:
        if attribute not in content:
            return ERROR_INVALID_MESSAGE

    # Validate the jwt
    try:
        payload = verify_jwt(request)
    except AuthError:
        return  ERROR_UNAUTHORIZED_MESSAGE

    user_sub = payload['sub']
    query = client.query(kind=USERS)

    # Check if user if admin
    query.add_filter("sub", "=", user_sub)
    query_result = list(query.fetch())
    print("query_result:", query_result)

    # Return error if there is no such user
    if len(query_result) == 0:
        return ERROR_PERMISSION_MESSAGE
    
    # Return error if requester is not admin
    requester = query_result[0]
    print(requester)
    if requester["role"] != "admin":
        return ERROR_PERMISSION_MESSAGE
    
    # Check if instructor_id exist
    instructor_id = content["instructor_id"]
    instructor_key = client.key(USERS, instructor_id)
    instructor = client.get(instructor_key)
    if instructor["role"] != "instructor":
        return ({"Error": "The value of instructor_id is invalid"}, 409)
    
    new_course = datastore.entity.Entity(key=client.key("courses"))
    new_course.update({"subject": content["subject"], 
                       "number":content["number"],
                       "title": content["title"],
                       "term": content["term"],
                       "instructor_id": content["instructor_id"]})
    client.put(new_course)
    course_id = new_course.key.id
    response = dict(new_course)
    response ={
        "id": course_id,
        "instructor_id" : content["instructor_id"],
        "number": content["number"],
        "self": request.host_url + "courses/" + str(course_id),
        "subject": content["subject"],
        "term" : content["term"],
        "title" : content["title"]
    }
    return response, 201

# 8 Get all courses
@app.route('/courses', methods=['GET'])
def get_all_courses():
    limit = request.args.get('limit', default=3, type=int)
    offset = request.args.get('offset', default=0, type=int)

    query = client.query(kind=COURSES)
    query.order = ["subject"]
    results = list(query.fetch(limit=limit+1, offset=offset))

    courses = []

    for c in results[:limit]:
        course_id = c.key.id
        course = {
            "id": course_id,
            "instructor_id":c["instructor_id"],
            "number":c["number"],
            "self": request.host_url.rstrip("/") + "/courses/" + str(course_id),
            "subject":c["subject"],
            "term":c["term"],
            "title":c["title"]
        }
        courses.append(course)
    
    response = {
        "courses":courses
    }

    if len(results) > limit:
        next_offset = offset + limit
        response["next"]=f"{
            request.host_url.rstrip("/") 
            + "/courses?limit=" 
            + str(limit) 
            + "&offset=" 
            + str(next_offset)
        }"

    return response, 200

# 9 Get a course
@app.route('/' + COURSES + '/<int:course_id>', methods=['GET'])
def get_a_course(course_id):

    # Check if course exists
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)
    if not course:
        return ERROR_NOT_FOUND_MESSAGE
    
    response = {
            "id": course_id,
            "instructor_id":course["instructor_id"],
            "number":course["number"],
            "self": request.host_url.rstrip("/") + "/courses/" + str(course_id),
            "subject":course["subject"],
            "term":course["term"],
            "title":course["title"]
        }
    
    return response, 200

# 10 Update a course, used with admin
@app.route('/' + COURSES + '/<int:course_id>', methods=['PATCH'])
def update_a_course(course_id):
    content = request.get_json()

    # Validate the jwt
    try:
        payload = verify_jwt(request)
    except AuthError:
        return  ERROR_UNAUTHORIZED_MESSAGE

    # Check if course exist
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)
    if not course:
        return ERROR_PERMISSION_MESSAGE
    
    # Check if user is admin
    user_sub = payload['sub']
    query = client.query(kind=USERS)
    query.add_filter("sub", "=", user_sub)
    query_result = list(query.fetch())
    print("query_result:", query_result)

    ## Return error if there is no such user
    if len(query_result) == 0:
        return ERROR_PERMISSION_MESSAGE
    
    ## Return error if requester is not admin
    requester = query_result[0]
    if requester["role"] != "admin":
        return ERROR_PERMISSION_MESSAGE
    
    # When updating instructor, check if instructor exist
    if "instructor_id" in content:
        instructor_id = content["instructor_id"]
        instructor_key = client.key(USERS, instructor_id)
        instructor = client.get(instructor_key)
        if instructor is None:
            return ({"Error": "The value of instructor_id is invalid"}, 409)
        if instructor["role"] != "instructor":
            return ({"Error": "The value of instructor_id is invalid"}, 409)
        else:
            course["instructor_id"] = content["instructor_id"]
    
    # Update the rest only if they aera specified in the request
    if "subject" in content:
        course["subject"] = content["subject"]

    if "number" in content:
        course["number"] = content["number"]

    if "title" in content:
        course["title"] = content["title"]

    if "term" in content:
        course["term"] = content["term"]

    course["id"] = course_id
    course["self"] = request.host_url + "courses/" + str(course_id)

    return course, 200

# 11 Delete a course, used it with admin
@app.route('/' + COURSES + '/<int:course_id>', methods=['DELETE'])
def delete_a_course(course_id):
    
    # Validate the jwt
    try:
        payload = verify_jwt(request)
    except AuthError:
        return  ERROR_UNAUTHORIZED_MESSAGE
    
    # Check if course exist
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)
    if not course:
        return ERROR_PERMISSION_MESSAGE
    
    # Check if user is admin
    user_sub = payload['sub']
    query = client.query(kind=USERS)
    query.add_filter("sub", "=", user_sub)
    query_result = list(query.fetch())
    print("query_result:", query_result)

    ## Return error if there is no such user
    if len(query_result) == 0:
        return ERROR_PERMISSION_MESSAGE
    
    ## Return error if requester is not admin
    requester = query_result[0]
    if requester["role"] != "admin":
        return ERROR_PERMISSION_MESSAGE
    
    client.delete(course_key)

    return "", 204

# 12. Update enrollment in a course, used by admin and instructor of that course
@app.route('/' + COURSES + '/<int:course_id>' + '/students', methods=['PATCH'])
def update_enrollment(course_id):

    # Validate the jwt
    try:
        payload = verify_jwt(request)
    except AuthError:
        return  ERROR_UNAUTHORIZED_MESSAGE
    
    # Check if course exist
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)
    print(course)
    if not course:
        return ERROR_PERMISSION_MESSAGE
    
    # Check if user is admin or instructor of the course
    user_sub = payload['sub']
    query = client.query(kind=USERS)
    query.add_filter("sub", "=", user_sub)
    query_result = list(query.fetch())
    print("query_result:", query_result)

    ## Return error if there is no such user
    if len(query_result) == 0:
        return ERROR_PERMISSION_MESSAGE
    
    ## Return error if requester is not admin or insturctor of the course
    requester = query_result[0]
    if requester["role"] == "admin":
        pass
    elif requester["role"] == "instructor" and course["instructor_id"] == requester.key.id:
        pass
    else:
        return ERROR_PERMISSION_MESSAGE
    
    # Check if enrollment data in the arrays are valid
    ## check if common value exist in "add" and "remove"
    content = request.get_json()

    add_list = content["add"]
    remove_list = content["remove"]
    common_students = set(add_list) & set(remove_list)
    if common_students:
        return {"Error": "Enrollment data is invalid"}, 409
    
    ## check all id in list are students
    all_students_id = add_list + remove_list
    for student_id in all_students_id:
        student_key = client.key(USERS,student_id)
        student = client.get(student_key)
        
        if student is None:
            return {"Error": "Enrollment data is invalid"}, 409
        
        if student["role"] != "student":
            return {"Error": "Enrollment data is invalid"}, 409
    
    # Add students, if in add but already enrolled, skip; if in remove but not enrolled, skip
    if "students" not in course:
        course["students"] = []
    
    for student in add_list:
        if student not in course["students"]:
            course["students"].append(student)
    
    for student in remove_list:
        if student in course["students"]:
            course["students"].remove(student)
    
    client.put(course)
    return "", 200

# 13. Get enrollment for a course, used by admin or instructor of that course. 
@app.route('/' + COURSES + '/<int:course_id>' + '/students', methods=['GET'])
def get_enrollment(course_id):

    # Validate the jwt
    try:
        payload = verify_jwt(request)
    except AuthError:
        return  ERROR_UNAUTHORIZED_MESSAGE
    
    # Check if course exist
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)
    print(course)
    if not course:
        return ERROR_PERMISSION_MESSAGE
    
    # Check if user is admin or instructor of the course
    user_sub = payload['sub']
    query = client.query(kind=USERS)
    query.add_filter("sub", "=", user_sub)
    query_result = list(query.fetch())
    print("query_result:", query_result)

    ## Return error if there is no such user
    if len(query_result) == 0:
        return ERROR_PERMISSION_MESSAGE
    
    ## Return error if requester is not admin or insturctor of the course
    requester = query_result[0]
    if requester["role"] == "admin":
        pass
    elif requester["role"] == "instructor" and course["instructor_id"] == requester.key.id:
        pass
    else:
        return ERROR_PERMISSION_MESSAGE
    
    response = []
    if "students" in course:
        response = course["students"]


    return response, 200
        

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload          
        

# 1 User login
# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/users/login', methods=['POST'])
def login_user():
    content = request.get_json()

    # check if request body is valid
    if "username" not in content or "password" not in content:
        return ERROR_INVALID_MESSAGE
    
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password',
            'username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET,
            "scope": "openid profile email"
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)

    #check if login info is correct
    if r.status_code != 200:
        return ERROR_UNAUTHORIZED_MESSAGE
    
    login_info = r.json()
    print(login_info)
    return {"token" : login_info["id_token"]}, 200

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

