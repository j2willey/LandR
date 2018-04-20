from django.shortcuts import render, redirect
from django.contrib import messages
from django.urls import reverse
from pprint import pprint
from . models import *
from django.utils.crypto import get_random_string

# Create your views here.
def index(request):
    print("=index()=================================")
    pprint(request.session)
    context = {}
    return render(request,'login/index.html', context)

# Create your views here.
def welcome(request):
    print("=index()=================================")
    pprint(request.session)
    context = {}
    return render(request,'login/success.html', context)

# Create your views here.
def logout(request):
    print("=logout()=================================")
    pprint(request.session)
    if "sessionkey" in request.session and request.session["sessionkey"] != "":
        sessionkey = request.session["sessionkey"]
        users.objects.logoutSession(sessionkey)
    context = {}
    return render(request,'login/index.html', context)

def process(request):
    print("=index()=================================")
    action  = request.POST['action'].strip()  if 'action'  in request.POST else ""
    if "sessionkey" in request.session and request.session["sessionkey"] != "":
        sessionkey = request.session["sessionkey"]
    else: 
        sessionkey = get_random_string(length=14, allowed_chars='abcdefghijklmnopqrstuvxyz')
        request.session["sessionkey"] = sessionkey
    #id      = request.POST['id'].strip()     if 'id'      in request.POST else ""
    errors = []
    print("Action: " + action)
    print("input: ")
    pprint(request.POST.keys())
    if action == "registration":
        (errors, context) = users.objects.validate_registration(request.POST)
        if len(errors):
            # if the errors object contains anything, loop through each key-value pair and make a flash message
            pprint(errors)
            for tag, value in errors:
                print(tag, value)
                messages.error(request, value, extra_tags=tag)
            # redirect the user back to the form to fix the errors
            return redirect(reverse(index))
        else:
            # register user
            # try:
            users.objects.create(**context)
            #except
            # return error....
            messages.info(request, "successful registration", extra_tags='login')
            return redirect("/login/success")
    elif action == "login":
        (errors, context) = users.objects.login(request.POST, sessionkey)
        if len(errors):
            # if the errors object contains anything, loop through each key-value pair and make a flash message
            for tag, value in errors:
                print(tag, value)
                messages.error(request, value, extra_tags=tag)
            # redirect the user back to the form to fix the errors
            return redirect(reverse(index))
        else:
            messages.info(request, "successfully logged in", extra_tags='login')
            return redirect('/login/success')
    else:
        messages.error(request, "Unknown action")
        # redirect the user back to the form to fix the errors
        return redirect(reverse(index))

    messages.error(request, "Don't know how we got here")    
    return redirect(reverse(index))
 
