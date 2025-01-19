"""
URL configuration for cyberproj project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path

from django.conf import settings
from django.conf.urls.static import static
from userapp import views as user_views
from adminapp import views as admin_views


urlpatterns = [
    path('admin/', admin.site.urls),
    path('',user_views.index,name="index"),
    path('about',user_views.about,name="about"),
    path('contact',user_views.contact,name="contact"),
    path('services',user_views.services,name="services"),
    path('admin-login',user_views.admin_login,name="admin_login"),
    path('user-login',user_views.user_login,name="user_login"),
    path('user-dashboard',user_views.user_dashboard,name="user_dashboard"),
    path('user-register',user_views.user_register,name="user_register"),
    path('user-profile',user_views.user_profile,name="user_profile"),
    path('cyber-security',user_views.cyber_sec,name="cyber_sec"),
    path('otp-verification',user_views.otp,name="otp"),

    


    # admin urls
    path('admin-dashboard',admin_views.index,name="admin_dashboard"),
    path('manage-users',admin_views.all_users,name="all_users"),
    path('pending-users',admin_views.pending_users,name="pending_users"),
    path('upload-dataset',admin_views.upload_dataset,name="upload_dataset"),
    path('view-dataset/',admin_views.view_dataset,name="view_dataset"),
    path('attacks-analysis',admin_views.attacks_analysis,name="attacks_analysis"),
    path('graph-analysis',admin_views.graph_analysis,name="graph_analysis"),
    path('Gaussian-Naive-Bayes',admin_views.alg1,name="alg1"),
    path('Decision-Tree',admin_views.alg2,name="alg2"),
    path('Random-Forest',admin_views.alg3,name="alg3"),
    path('Logistic-Regression',admin_views.alg4,name="alg4"),
    path('Gradient-Boosting-Classifier',admin_views.alg5,name="alg5"),


    path('Accept-user/<int:user_id>/',admin_views.accept_user,name="accept_user"),
    path('Reject-user/<int:user_id>/',admin_views.reject_user,name="reject_user"),
    path('Delete-user/<int:user_id>/',admin_views.delete_user,name="delete_user"),
    path('logout',user_views.user_logout,name="log_out"),












]+static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
