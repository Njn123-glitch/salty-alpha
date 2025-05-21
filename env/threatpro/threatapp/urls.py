"""
URL configuration for threatpro project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
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
from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    
    path('dashboard', views.dashboard, name='dashboard'),
    path('index', views.index, name='index'),
    # path('upload-log/', views.upload_log, name='upload_log'),
    
    path('admin_dashboard', views.admin_dashboard, name='admin_dashboard'),
  
    path('admin_view', views.admin_view, name='admin_view'),
    
    path("register", views.register_view, name="register"),
    path("login", views.login_view, name="login"),
    path("logout", views.logout_view, name="logout"),
    
    path('upload_log_file/', views.upload_log_file, name='upload_log_file'),
    path('log_analysis_report/', views.log_analysis_report, name='log_analysis_report'),
    path('threat-chart/<int:log_id>/', views.threat_frequency_chart, name='threat_frequency_chart'),
    
    # path("check_reputation", views.check_reputation, name="reputation_check"),
    path("check_reputation", views.check_reputation, name="check_reputation"),
    # path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('report-incident/', views.report_incident, name='report_incident'),
    path('detailed-log/', views.detailed_log_analysis, name='detailed_log'),
    path('log_details', views.log_details, name='log_details'),
    
    
    path('threat_list', views.threat_list, name='threat_list'),
    
    path('add_threat', views.add_threat, name='add_threat'),
    path('threats/update/<int:threat_id>/', views.update_threat, name='update_threat'),
    path('threats/delete/<int:threat_id>/', views.delete_threat, name='delete_threat'),
    
    
    path('user_list_view', views.user_list_view, name='user_list_view'),
    path('delete_user/<int:id>', views.delete_user, name='delete_user'),
    
    path('admin-log-report', views.log_analysis_report, name='log_analysis_report'),
    
    path('enquiry_list', views.enquiry_list, name='enquiry_list'),
    path('test', views.test, name='test'),
    path('reg', views.reg, name='reg'),
]
