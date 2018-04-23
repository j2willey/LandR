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



# Create your views here.
def index(request):
    print("=index()=================================")
    pprint(request.session)
    context = {}
    return render(request,'login/index.html', context)

# Create your views here.
def welcome(request):
    print("=welcome()=================================")
    if not validate_session(request):
        return redirect('/')
    user  = request.session['user'].strip()  if 'user'  in request.session else "oops"
    context = { 'user' : user }
    return render(request,'login/success.html', context)

# Create your views here.
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
            messages.info(request, "successful registration", extra_tags='login')
            return redirect("/login/success")
    elif action == "login":
        errors = users.objects.login(request.POST, sessionkey)
        if len(errors):
            errors_to_messages(request, errors)
            return redirect(reverse(index))
        else:
            errors, request.session["user"] = sessions.objects.getSessionUser(sessionkey)
            messages.info(request, "successfully logged in", extra_tags='login')
            return redirect('/login/success')
    else:
        messages.error(request, "Unknown action")
        return redirect(reverse(index))

    messages.error(request, "Don't know how we got here")    
    return redirect(reverse(index))
 
