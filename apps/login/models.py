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
    if re.match("^[a-zA-Z]+ *[a-zA-Z]*$", name) == None:
        errors.append((tag, tag + " can only contain letters."))
    return errors

def validateQuote(tag, quote):
    errors = []
    if len(quote) < 10:
        errors.append((tag, tag + " should be at least 10 characters."))
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
            except Exception as e:
                print("ERROR: Creating user in db - " + str(e))
                errors["Error on creating user id in db" + e]
        return errors

    def login(self, postData, sessionkey):
        errors = []
        email   = postData['email'].strip()      if 'email'      in postData else ""
        password= postData['password'].strip()   if 'password'   in postData else ""
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
        if len(ss) == 1 : # and  ss[0].timeout_at > datetime.now():
            print("=logoutSession: found session to logout")
            ss[0].delete()
        return False

class sessionManager(models.Manager):
    def getSessionUser(self, sessionkey):
        errors = []
        user = {}
        try:
            ss = sessions.objects.get(session_key=sessionkey)
            user = { 'first_name' : ss.user.first_name,
                     'last_name'  : ss.user.last_name,
                     'email'      : ss.user.email,
                     'name'       : ss.user.first_name + " " + ss.user.last_name,
                     'id'         : ss.user.id }
        except Exception as e:
            print("ERROR: GetSessionUser Failed\n" + str(e))
            errors.append(("session","Session User missing.")) 
        return errors, user


class quotesManager(models.Manager):
    def add_quote(self, postData, user_id):
        print("=quotesManager.add_quote()=================================")
        errors = []
        name   = postData['by'].strip() if 'by' in postData else ""
        quote  = postData['quote'].strip() if 'quote' in postData else ""
        errors.extend(validateName("name", name))
        errors.extend(validateQuote("quote", quote))
        qs = quotes.objects.filter(quote = quote)
        if len(qs) != 0:
            errors.append(("quote","quote already exists. Added by " + i.added_by.first_name))
        if len(errors) == 0:
            try:
                user = users.objects.get(id = user_id)
                quote = quotes.objects.create(name = name, quote = quote, posted_by_id = user_id)
            except Exception as e:
                print("ERROR:" + str(e))
                errors.append(("quote","problem creating quote " + str(e)))                        
        return errors

    def getFavQuotes(self, user_id):
        favorites = [] 
        others = []
        errors = []
        try:
            favorites = quotes.objects.filter(favorite_of = user_id)
            others    = quotes.objects.filter(~Q(favorite_of = user_id))
        except Exception as e:
            print("ERROR:" + str(e))
            errors.append(("ERROR","problem getting quotes " + str(e)))                        
        return errors, favorites, others        


    def favorite(self, quote_id, user_id):
        errors = []
        try:
            user  = users.objects.get(id = user_id)
            quote = quotes.objects.get(id = quote_id)
            quote.favorite_of.add(user)
        except Exception as e:
            print("ERROR:" + str(e))
            errors.append(("item","problem favoriting quote " + str(e)))                        
        return errors

    def unfavorite(self, quote_id, user_id):
        errors = []
        try:
            user  = users.objects.get(id = user_id)
            quote = quotes.objects.get(id = quote_id)
            quote.favorite_of.remove(user)
        except Exception as e:
            print("ERROR:" + str(e))
            errors.append(("item","problem unfavoriting quote " + str(e)))                        
        return errors


    def getUser(self, user_id):
        errors = []
        theUser = {}
        try:
            user  = users.objects.get(id = user_id)
            posts = quotes.objects.filter(posted_by = user_id)
            theUser = { 'name'   : user.first_name + " " + user.last_name, 
                        'count'  : len(posts),
                        'quotes' : posts
                        }
            print(len(posts))
        except Exception as e:
            print("ERROR:" + str(e))
            errors.append(("ERROR","problem getting list " + str(e)))                        
        return errors, theUser


class favoritesManager(models.Manager):
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
            except Exception as e:
                print("ERROR:" + str(e))
                errors.append(("item","problem adding item " + str(e)))                        
        return errors

    def remove_item(self, user_id, item_id):
        errors = []
        if len(errors) == 0:
            try:
                item = items.objects.get(id = item_id)
                wishlist = wishlists.objects.get(id = user_id)
                wishlist.items.remove(item)
            except Exception as e:
                print("ERROR:" + str(e))
                errors.append(("item","problem adding item " + str(e)))                        
        return errors

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


class quotes(models.Model):
    name        = models.CharField(max_length=255)
    quote       = models.TextField()
    posted_by   = models.ForeignKey(users,related_name="post")
    favorite_of = models.ManyToManyField(users, related_name="favorites")
    objects     = quotesManager()

