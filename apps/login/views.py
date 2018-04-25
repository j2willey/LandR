from django.shortcuts import render, redirect
from django.contrib import messages
from django.urls import reverse
from pprint import pprint
from . models import *
from django.utils.crypto import get_random_string

def errors_to_messages(request, errors):
    print("Errors:")
    pprint(errors)
    for tag, value in errors:
        messages.error(request, value, extra_tags=tag)

def validate_session(request):
    errors = []
    if "sessionkey" not in request.session or request.session["sessionkey"] == "":
        errors.append(("session", "session key not found."))
    else:
        sessionkey = request.session["sessionkey"]
        errors = users.objects.validateSession(sessionkey)
    if len(errors):
        errors_to_messages(request, errors)
        return False
    return True

def user_info(request):
    errors, user = sessions.objects.getSessionUser(request.session["sessionkey"])
    if len(errors):
        errors_to_messages(request)
    return user

def index(request):
    print("=index()=================================")
    pprint(request.session)
    context = {}
    return render(request,'login/index.html', context)

def welcome(request):
    print("=welcome()=================================")
    if not validate_session(request):
        return redirect('/')
    user = user_info(request)
    context = { 'user' : user }
    return render(request,'login/dashboard.html', context)

def quote(request):
    print("=quote()=================================")
    if not validate_session(request):
        return redirect('/')
    user = user_info(request)
    errors, userFavorites, others = quotes.objects.getFavQuotes(user['id'])
    errors = []
    quotableQuotes = others                       
    favQuotes      = userFavorites
    errors_to_messages(request, errors)
    context = { 'user' : user , 'quotableQuotes' : quotableQuotes, 'favQuotes' : favQuotes}
    return render(request,'login/quotes.html', context)


def add_quote(request):
    print("=add_quote()=================================")
    if not validate_session(request):
        return redirect('/')
    user = user_info(request)
    if request.method == "POST":
        print("this is a POST")
        errors = quotes.objects.add_quote(request.POST, user['id'])
        if len(errors) == 0:
            messages.info(request, "successfully added quote", extra_tags='info')
        else:
            errors_to_messages(request, errors)
            return redirect("/login/quotes")
    return redirect("/login/quotes")

def add_favorite(request, quote_id):
    print("=add_favorite()=================================")
    if not validate_session(request):
        return redirect('/')
    user = user_info(request)
    errors = quotes.objects.favorite(quote_id, user['id'])
    if len(errors):
        errors_to_messages(request, errors)
    return redirect("/login/quotes")

def un_favorite(request, quote_id):
    print("=un_favorite()=================================")
    if not validate_session(request):
        return redirect('/')
    user = user_info(request)
    errors = quotes.objects.unfavorite(quote_id, user['id'])
    if len(errors):
        errors_to_messages(request, errors)
    return redirect("/login/quotes")

def display_user(request, user_id):
    print("=display_item()=================================")
    if not validate_session(request):
        return redirect('/')
    user = user_info(request)
    errors, theUser = quotes.objects.getUser(user_id)
    context = { 'user' : user, 'theUser' : theUser }
    return render(request,'login/display_user.html', context)



def logout(request):
    print("=logout()=================================")
    pprint(request.session)
    if "sessionkey" in request.session and request.session["sessionkey"] != "":
        sessionkey = request.session["sessionkey"]
        users.objects.logoutSession(sessionkey)
        request.session["sessionkey"] = ""
    return redirect('/')

def process(request):
    print("=process()=================================")
    action  = request.POST['action'].strip()  if 'action'  in request.POST else ""
    if "sessionkey" in request.session and request.session["sessionkey"] != "":
        sessionkey = request.session["sessionkey"]
    else: 
        sessionkey = get_random_string(length=14, allowed_chars='abcdefghijklmnopqrstuvxyz')
        request.session["sessionkey"] = sessionkey
    errors = []
    print("Action: " + action)
    print("input: ")
    pprint(request.POST.keys())
    if action == "registration":
        errors = users.objects.register(request.POST)
        if len(errors) == 0:
            errors = users.objects.login(request.POST, sessionkey)
        if len(errors):
            errors_to_messages(request, errors)
            return redirect(reverse(index))
        else:
            sessionkey = get_random_string(length=14, allowed_chars='abcdefghijklmnopqrstuvxyz')
            user = user_info(request)
            messages.info(request, "successful registration", extra_tags='login')
            return redirect("/login/quotes")
    elif action == "login":
        errors = users.objects.login(request.POST, sessionkey)
        if len(errors):
            errors_to_messages(request, errors)
            return redirect(reverse(index))
        else:
            user = user_info(request)
            pprint(user)
            request.session["user"] = user['name']
            messages.info(request, "successfully logged in", extra_tags='login')
            return redirect('/login/quotes')
    else:
        messages.error(request, "Unknown action")
        return redirect(reverse(index))

    messages.error(request, "Don't know how we got here")    
    return redirect(reverse(index))
 
