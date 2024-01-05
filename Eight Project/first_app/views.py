from django.shortcuts import render, redirect
from .forms import RegisterForm, ChangeUserData
from django.contrib import messages
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm, SetPasswordForm
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash

def home(request):
    return render(request, './homepage.html')


def signup(request):
    if not request.user.is_authenticated:
        if request.method == 'POST':
            form = RegisterForm(request.POST)
            if form.is_valid():
                messages.success(request, 'Account created successfully')
                form.save()
                print(form.cleaned_data)
        else:
            form = RegisterForm()
        return render(request, './signup.html', {'form': form})
    else:
        return redirect('profile')


def user_login(request):
    if request.method == 'POST':
        log_form = AuthenticationForm(request=request, data=request.POST)
        if log_form.is_valid():
            name = log_form.cleaned_data['username']
            userpass = log_form.cleaned_data['password']
            # check kortechi user database e ache kina
            user = authenticate(username=name, password=userpass)
            if user is not None:
                login(request, user)
                return redirect('profile')  # profile page e redirect korbe
            
    else:
        log_form = AuthenticationForm()
    return render(request, './login.html', {'form': log_form})


def profile(request):
    if request.user.is_authenticated:
        if request.method == 'POST':
            profile_form = ChangeUserData(request.POST, instance=request.user)
            if profile_form.is_valid():
                messages.success(request, 'Account updated successfully')
                profile_form.save()
        else:
            profile_form = ChangeUserData(instance=request.user)
        return render(request, './profile.html', {'form': profile_form})
    else:
        return redirect('signup')


def user_logout(request):
    logout(request)
    return redirect('login')


def pass_change(request):
    if request.user.is_authenticated:
        if request.method == 'POST':
            pass_form = PasswordChangeForm(user=request.user, data=request.POST)
            if pass_form.is_valid():
                pass_form.save()
                
                update_session_auth_hash(request, pass_form.user)
                return redirect('profile')
        else:
            pass_form = PasswordChangeForm(user=request.user)
        return render(request, './passchange.html', {'form': pass_form})
    else:
        return redirect('login')


def pass_change2(request):
    if request.user.is_authenticated:
        if request.method == 'POST':
            pass_form = SetPasswordForm(user=request.user, data=request.POST)
            if pass_form.is_valid():
                pass_form.save()
                
                update_session_auth_hash(request, pass_form.user)
                return redirect('profile')
        else:
            pass_form = SetPasswordForm(user=request.user)
        return render(request, './passchange.html', {'form': pass_form})
    else:
        return redirect('login')


def change_user_data(request):
    if request.user.is_authenticated:
        if request.method == 'POST':
            user_form = ChangeUserData(request.POST, instance=request.user)
            if user_form.is_valid():
                messages.success(request, 'Your Account updated successfully')
                user_form.save()
        else:
            user_form = ChangeUserData()
        return render(request, './profile.html', {'form': user_form})
    else:
        return redirect('signup')
