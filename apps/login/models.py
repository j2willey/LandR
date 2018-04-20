from django.db import models
from datetime import datetime, timedelta
from pprint import pprint
import bcrypt
import re

# Create your models here.

def validateName(tag, name):
    errors = []
    if len(name) < 2:
        errors.append((tag, tag + " should be at least 2 characters."))
    if re.match("^[a-zA-Z]+ *[a-zA-Z]+$", name) == None:
        errors.append((tag, tag + " can only contain letters."))
    return errors

def validateEmail(email):
    #if re.match("^.+@([?)[a-zA-Z0-9-.]+.([a-zA-Z]{2,3}|[0-9]{1,3})(]?)$", email) != None:
    errors = []
    if len(email) < 7 or (re.match("^.+@[a-zA-Z0-9-.]+.([a-zA-Z]{2,3}|[0-9]{1,3})$", email) == None):
        errors.append(("email","Email address must be a valid email."))
    u = users.objects.filter(email = email)
    if len(u) != 0:
        errors.append(("email","Email address already registered."))        
    return errors

def validatePassword(pw, cpw):
    errors = []
    minPasswordLen = 3
    if len(pw) < minPasswordLen:
        errors.append(("password","Password must be atleast %s characters long." % (minPasswordLen)))
    if re.match("^.*[A-Z].*$", pw) == None:
        errors.append(("password","Password must contain atleast one uppercase letter."))
    if re.match("^.*[a-z].*$", pw) == None:
        errors.append(("password","Password must contain atleast one lowercase letter."))
    if re.match("^.*[0-9].*$", pw) == None:
        errors.append(("password","Password must contain atleast one number."))
    return errors

def userSessionUpdate(sessionkey, uid = 0):
    errors = []
    ss = sessions.objects.filter(user_id = uid, session_key=sessionkey)
    if len(ss) == 1:
        ss[0].login_at = datetime.now()
        ss[0].timeout_at = datetime.now() + timedelta(minutes=5)
        ss[0].save()
        # update ss
    elif len(ss) == 0 and uid != 0:
        timeout = datetime.now() + timedelta(minutes=5)
        sessions.objects.create(user_id = uid, session_key=sessionkey, timeout_at=timeout)
        # insert ss
    else:
        errors.append(("login","Internal Session error."))
    return errors

class usersManager(models.Manager):
    def validate_registration(self, postData):
        errors = []
        fname   = postData['first_name'].strip() if 'first_name' in postData else ""
        lname   = postData['last_name'].strip()  if 'last_name'  in postData else ""
        email   = postData['email'].strip()      if 'email'      in postData else ""
        password= postData['password'].strip()   if 'password'   in postData else ""
        confrmpw= postData['confrmpw'].strip()   if 'confrmpw'   in postData else ""
        print("fname: " + fname)
        print("lname: " + lname)
        print("email: " + email)
        errors.extend(validateName("first_name", fname))
        errors.extend(validateName("last_name", lname))
        errors.extend(validateEmail(email))
        errors.extend(validatePassword(password, confrmpw))
        password_hash=bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        context = {'first_name' : fname, 
                   'last_name'  : lname,
                   'email'      : email,
                   "password"   : password_hash}
        return(errors, context)

    def login(self, postData, sessionkey):
        errors = []
        email   = postData['email'].strip()      if 'email'      in postData else ""
        password= postData['password'].strip()   if 'password'   in postData else ""
        print("email: " + email)
        password_hash=password #bcrypt it
        # Retrive PWHashfrom DB
        u = users.objects.filter(email = email)
        if len(u) == 0:
            errors.append(("login","Login failed."))        
        else:
            uid = u[0].id 
            hashpw = u[0].password
            if not bcrypt.checkpw(password.encode(), hashpw.encode()):
                errors.append(("login","Login failed.")) 
            else:
                userSessionUpdate(sessionkey, uid)
        context = { 'email' : email }       
        return errors, context

    def validateSession(self, sessionkey):
        errors = []
        ss = sessions.objects.filter(session_key=sessionkey)
        if len(ss) == 1: # and ss[0].timeout_at > datetime.now():
            return True
        else:   # Update timeout since we have activity
            userSessionUpdate(sessionkey, uid)
        return False

    def logoutSession(self, sessionkey):
        errors = []
        ss = sessions.objects.filter(session_key=sessionkey)
        #print( "timeout_at "  + str(type(ss[0].timeout_at))) 
        #print("now()  " + str(type( datetime.now())))
        if len(ss) == 1 : # and  ss[0].timeout_at > datetime.now():
            print("=logoutSession: found session to logout")
            ss[0].delete()
        return False




class users(models.Model):
    first_name = models.CharField(max_length=255)
    last_name  = models.CharField(max_length=255)
    email      = models.CharField(max_length=255)
    password   = models.CharField(max_length=255, default="*")
    created_at = models.DateTimeField(auto_now_add=True) 
    updated_at = models.DateTimeField(auto_now=True)
    objects = usersManager()

class sessions(models.Model):
    session_key= models.CharField(max_length=255)
    login_at   = models.DateTimeField(auto_now_add=True) 
    timeout_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True) 
    updated_at = models.DateTimeField(auto_now=True)
    user       = models.ForeignKey(users,related_name="sessions")