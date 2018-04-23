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

def welcome(request):
    print("=welcome()=================================")
    if not validate_session(request):
        return redirect('/')
    user  = request.session['user'].strip()  if 'user'  in request.session else "oops"
    context = { 'user' : user }
    return render(request,'login/dashboard.html', context)

def dashboard(request):
    print("=dashboard()=================================")
    if not validate_session(request):
        return redirect('/')
    user  = request.session['user'].strip()  if 'user'  in request.session else "oops"
    errors, fname, user_id = sessions.objects.getSessionUser(request.session["sessionkey"])
    errors, wishlist, others = wishlists.objects.getWishLists(user_id)
    pprint(errors)
    pprint(wishlist)
    pprint(others)
    errors_to_messages(request, errors)
    context = { 'user' : user , 'userwishlist' : wishlist, 'otherswishlist' : others}
    return render(request,'login/dashboard.html', context)

def add_item(request, item_id):
    print("=create_item()=================================")
    if not validate_session(request):
        return redirect('/')
    user  = request.session['user'].strip()  if 'user'  in request.session else "oops"
    sessionkey = request.session["sessionkey"]
    errors, fname, user_id = sessions.objects.getSessionUser(sessionkey)
    context = { 'user' : user }
    errors = items.objects.add_item(user_id, item_id)
    if len(errors) == 0:
        messages.info(request, "successfully added item", extra_tags='info')
    else:
        errors_to_messages(request, errors)
    return redirect("/login/dashboard")





def create_item(request):
    print("=create_item()=================================")
    if not validate_session(request):
        return redirect('/')
    user  = request.session['user'].strip()  if 'user'  in request.session else "oops"
    sessionkey = request.session["sessionkey"]
    errors, fname, user_id = sessions.objects.getSessionUser(sessionkey)
    context = { 'user' : user }
    if request.method == "POST":
        print("this is a POST")
        errors = items.objects.create_item(request.POST, user_id)
        if len(errors) == 0:
            messages.info(request, "successfully created item", extra_tags='info')
        else:
            errors_to_messages(request, errors)
            return redirect("/login/wish_items/create")
        return redirect("/login/dashboard")
    else:
        print("must be a get a GET")
    return render(request,'login/create_item.html', context)

def display_item(request, item_id):
    print("=display_item()=================================")
    if not validate_session(request):
        return redirect('/')
    user  = request.session['user'].strip()  if 'user'  in request.session else "oops"
    errors, item = items.objects.getItem(item_id)
    pprint(item)
    context = { 'user' : user , 'item' : item}
    print("=display_item()=============================end=")
    return render(request,'login/display_item.html', context)

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
            return redirect("/login/dashboard")
    elif action == "login":
        errors = users.objects.login(request.POST, sessionkey)
        if len(errors):
            errors_to_messages(request, errors)
            return redirect(reverse(index))
        else:
            errors, request.session["user"], user_id = sessions.objects.getSessionUser(sessionkey)
            messages.info(request, "successfully logged in", extra_tags='login')
            return redirect('/login/dashboard')
    else:
        messages.error(request, "Unknown action")
        return redirect(reverse(index))

    messages.error(request, "Don't know how we got here")    
    return redirect(reverse(index))
 
