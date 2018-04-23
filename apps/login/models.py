from django.db import models
from django.db.models import Q
from datetime import datetime, timedelta
from pprint import pprint
import bcrypt
import re

# Create your models here.

def print_postdata(funcname, postData):
    print("=%s=======================\npostData:" % (funcname))
    pprint(postData)

def validateName(tag, name):
    errors = []
    if len(name) < 3:
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
    ss = sessions.objects.filter(session_key=sessionkey)
    if len(ss) == 1:
        ss[0].login_at = datetime.now()
        ss[0].timeout_at = datetime.now() + timedelta(minutes=5)
        # TODO:  Time stamp not quite  compatible as is
        #ss[0].save()
    elif len(ss) == 0 and uid != 0:
        timeout = datetime.now() + timedelta(minutes=5)
        sessions.objects.create(user_id = uid, session_key=sessionkey, timeout_at=timeout)
    else:
        errors.append(("login","Internal Session error."))
    return errors

class usersManager(models.Manager):
    def validate_registration(self, postData):
        print("validate_registration", postData)
        errors = []
        fname   = postData['first_name'].strip() if 'first_name' in postData else ""
        lname   = postData['last_name'].strip()  if 'last_name'  in postData else ""
        email   = postData['email'].strip()      if 'email'      in postData else ""
        password= postData['password'].strip()   if 'password'   in postData else ""
        confrmpw= postData['confrmpw'].strip()   if 'confrmpw'   in postData else ""
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

    def register(self, postData):
        (errors, context) = self.validate_registration(postData)
        if len(errors) == 0:
            try:
                u = users.objects.create(**context)
                wishlists.objects.create(user = u, name = u.first_name + " " + u.last_name + "'s Wish List")                
            except Exception as e:
                print("ERROR: Creating user in db - " + str(e))
                errors["Error on creating user id in db" + e]
        return errors

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
        return errors

    def validateSession(self, sessionkey):
        errors = []
        ss = sessions.objects.filter(session_key=sessionkey)
        print("=validateSession=======================")
        if len(ss) == 1: # and ss[0].timeout_at > datetime.now():
            userSessionUpdate(sessionkey, ss[0].user_id)
        else:
            print("Session not valid. May have timed out.")
            errors.append(("session","Session not valid. May have timed out.")) 
        return errors

    def logoutSession(self, sessionkey):
        errors = []
        ss = sessions.objects.filter(session_key=sessionkey)
        #print( "timeout_at "  + str(type(ss[0].timeout_at))) 
        #print("now()  " + str(type( datetime.now())))
        if len(ss) == 1 : # and  ss[0].timeout_at > datetime.now():
            print("=logoutSession: found session to logout")
            ss[0].delete()
        return False

class sessionManager(models.Manager):
    def getSessionUser(self, sessionkey):
        errors = []
        try:
            ss = sessions.objects.get(session_key=sessionkey)
            print("=getSessionUser=======================" + ss.user.first_name)
        except Exception as e:
            print("ERROR: GetSessionUser Failed")
            errors.append(("session","Session User missing.")) 
        return errors, ss.user.first_name, ss.user_id


class itemManager(models.Manager):
    def create_item(self, postData, user_id):
        errors = []
        item_name   = postData['item_name'].strip() if 'item_name' in postData else ""
        errors.extend(validateName("item_name", item_name))
        i = items.objects.filter(name = item_name)
        if len(i) != 0:
            errors.append(("item","item already exists. Added by " + i.added_by.first_name))
        if len(errors) == 0:
            try:
                user = users.objects.get(id = user_id)
                item = items.objects.create(name = item_name, added_by = user)
                wishlist = wishlists.objects.get(user = user )
                #wish = wishlist.items.add(items = item)
                wish = item.wishlists.add(wishlist)
                print("=create_item=======================7")
            except Exception as e:
                print("ERROR:" + str(e))
                errors.append(("item","problem creating item " + str(e)))                        
        return errors

    def add_item(self, user_id, item_id):
        errors = []
        if len(errors) == 0:
            try:
                user = users.objects.get(id = user_id)
                item = items.objects.get(id = item_id)
                # TODO confirm item is not in list
                # if len(i) != 0:
                #     errors.append(("item","item already exists. Added by " + i.added_by.first_name))
                wishlist = wishlists.objects.get(user = user )
                wish = item.wishlists.add(wishlist)
                print("=user_item=======================7")
            except Exception as e:
                print("ERROR:" + str(e))
                errors.append(("item","problem adding item " + str(e)))                        
        return errors

    def getItem(self, item_id):
        errors = []
        try:
            print("=getItem=======================1")
            item = items.objects.get(id = item_id)
            pprint(item)
            print("=getItem=======================3")
        except Exception as e:
            print("ERROR:" + str(e))
            errors.append(("ERROR","problem getting list " + str(e)))                        
        return errors, item   


class wishlistManager(models.Manager):
    def getWishLists(self, user_id):
        wishlist = [] 
        others = []
        errors = []
        try:
            print("=getWishLists=======================1")
            #wishlist = wishlists.objects.get(user_id = user_id)
            wishlist = items.objects.filter(wishlists = wishlists.objects.get(user_id = user_id))
            print("=getWishLists=======================2")
            #others   = wishlists.objects.filter(~Q(user_id = user_id))
            others = items.objects.filter(~Q(wishlists = wishlists.objects.get(user_id = user_id)))
            print("=getWishLists=======================3")
        except Exception as e:
            print("ERROR:" + str(e))
            errors.append(("ERROR","problem getting list " + str(e)))                        
        return errors, wishlist, others        

    def getSessionUser(self, sessionkey):
        pass

class users(models.Model):
    first_name = models.CharField(max_length=255)
    last_name  = models.CharField(max_length=255)
    email      = models.CharField(max_length=255)
    password   = models.CharField(max_length=255, default="*")
    created_at = models.DateTimeField(auto_now_add=True) 
    updated_at = models.DateTimeField(auto_now=True)
    objects    = usersManager()

class sessions(models.Model):
    session_key= models.CharField(max_length=255)
    login_at   = models.DateTimeField(auto_now_add=True) 
    timeout_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True) 
    updated_at = models.DateTimeField(auto_now=True)
    user       = models.ForeignKey(users,related_name="sessions")
    objects    = sessionManager()

class wishlists(models.Model):
    name       = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True) 
    updated_at = models.DateTimeField(auto_now=True)
    user       = models.ForeignKey(users,related_name="wishlist")
    objects    = wishlistManager()
    
class items(models.Model):
    name       = models.CharField(max_length=255)
    added_by   = models.ForeignKey(users,related_name="items")
    added_date = models.DateTimeField(auto_now_add=True) 
    created_at = models.DateTimeField(auto_now_add=True) 
    updated_at = models.DateTimeField(auto_now=True)
    wishlists  = models.ManyToManyField(wishlists, related_name="items")
    objects    = itemManager()

