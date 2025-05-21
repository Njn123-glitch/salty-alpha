from django.shortcuts import render,redirect,get_object_or_404,HttpResponse
from django.contrib.auth.decorators import login_required
from .models import ThreatLog, ThreatDetection, IPReputation, IncidentReport,Enquiry
from .forms import IncidentReportForm, EnquiryForm
import csv
import io
import matplotlib.pyplot as plt
import base64
from django.db.models import Count


from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.db.models import Count
import matplotlib.pyplot as plt
import io, base64, csv
from .models import ThreatLog, ThreatDetection, IncidentReport, IPReputation
from .models import ThreatLog

from django.contrib.auth import login


from .forms import RegisterForm
from django.contrib import messages
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import authenticate, login, logout


from django.contrib.auth import authenticate, login as auth_login

from django.contrib.auth import authenticate, login as auth_login  # Rename login
from django.shortcuts import render, redirect
from django.contrib.auth.forms import AuthenticationForm
from django.contrib import messages
from .forms import RegisterForm


from .forms import RegisterForm
from django.contrib.auth import login

from django.contrib import messages
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import authenticate, login, logout

from django.contrib.auth import get_user_model


def register_view(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)  
            return redirect("login")  
    else:
        form = RegisterForm()
    
    return render(request, "accounts/register.html", {"form": form})


def login_view(request):
    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get("username")
            password = form.cleaned_data.get("password")
            user = authenticate(request, username=username, password=password)  # Pass request to authenticate
            
            if user is not None:
                login(request, user)  # Ensure user is authenticated before calling login
                
                if user.is_superuser:
                    return redirect("admin_dashboard")  # Redirect superuser
                return redirect("check_reputation")  # Redirect regular user
            else:
                messages.error(request, "Invalid username or password")
        else:
            messages.error(request, "Invalid username or password")
    
    form = AuthenticationForm()
    return render(request, "accounts/login.html", {"form": form})


def logout_view(request):
    logout(request)
    return redirect("index")

def admin_dashboard(request):
    return render(request, 'admin_pages/admin_dashboard.html')


def logout_view(request):
    logout(request)
    return redirect("login")

def index(request):
    if request.method == 'POST':
        form = EnquiryForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Your message has been sent. Thank you!")
            return redirect('index')  # or whichever URL name you'd like to use
        else:
            messages.error(request, "Error in form submission. Please check your inputs.")
    else:
        form = EnquiryForm()
    return render(request, 'index.html', {'form': form})

def enquiry_list(request):
    enquiries = Enquiry.objects.all().order_by('-id')
    return render(request, 'admin_pages/enquiry_list.html', {'enquiries': enquiries})


@login_required
def dashboard(request):
    logs = ThreatLog.objects.filter(user=request.user)
    incidents = IncidentReport.objects.filter(user=request.user)
    
    # Fetch detected threats for this user
    threats = ThreatDetection.objects.filter(log__user=request.user)

    # Count threats by severity for chart
    threat_counts = threats.values('severity').annotate(count=Count('id'))

    # Generate Pie Chart for Threat Severity
    labels = [entry['severity'] for entry in threat_counts]
    values = [entry['count'] for entry in threat_counts]

    if labels and values:  # Prevent empty chart errors
        fig, ax = plt.subplots()
        ax.pie(values, labels=labels, autopct='%1.1f%%', startangle=90, colors=['green', 'yellow', 'red'])
        ax.axis('equal')

        # Convert chart to Base64 image
        buffer = io.BytesIO()
        plt.savefig(buffer, format="png")
        buffer.seek(0)
        image_data = base64.b64encode(buffer.getvalue()).decode()
        buffer.close()
    else:
        image_data = None  # No data available

    return render(request, 'dashboard.html', {
        'logs': logs,
        'incidents': incidents,
        'threats': threats, 
        'threat_chart': image_data
    })
    
           
import re
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.core.files.storage import default_storage
from django.utils.timezone import make_aware
from datetime import datetime
from .models import ThreatLog, ThreatDetection
from .forms import LogUploadForm
from collections import defaultdict


THREAT_PATTERNS = {
    "SQL Injection": (r"(UNION\s+SELECT|SELECT\s+\*.*FROM|INSERT\s+INTO|DROP\s+TABLE)", "High"),
    "XSS Attack": (r"(<script>|javascript:|onerror=)", "High"),
    "Unauthorized Access": (r"(401|403)", "High"),
    "Brute Force Attempt": (r"(failed login|password incorrect)", "Medium"),
    "Directory Traversal": (r"(\.\./|\.\.\\|/etc/passwd|C:\\windows\\)", "Medium"),
    "Web Scraping": (r"(Scrapy|Python-urllib|wget|curl)", "Low"),
    "404 Probing": (r"(404)", "Low"),
    "Buffer Overflow": (r"([A-Za-z0-9]{1000,})", "High"),  # Long strings (1000+ chars)
    "Command Injection": (r"(\b(wget|curl|rm\s+-rf|chmod\s+\+x)\b)", "High"),
    "Malicious User Agent": (r"(sqlmap|nmap|nikto|metasploit)", "High"),
    "Port Scanning": (r"(SYN_SCAN|NMAP_SCAN)", "Medium"),
    "DDoS Attack": (r"(\b(?:\d{1,3}\.){3}\d{1,3}\b).*?(GET|POST).*?\1", "High"),  # Same IP repeated in logs
    "Malicious File Upload": (r"(upload.*?\.(exe|php|jsp|aspx|sh|bat))", "High"),
}



def upload_log_file(request):
    """
    Allows user to upload log files
    """
    if request.method == 'POST':
        form = LogUploadForm(request.POST, request.FILES)
        if form.is_valid():
            log_entry = form.save(commit=False)
            log_entry.user = request.user
            log_entry.save()

            analyze_logs(log_entry)  

            return redirect('log_analysis_report')

    else:
        form = LogUploadForm()

    return render(request, 'upload_log.html', {'form': form})


def analyze_logs(log_entry):
    """
    Reads and processes log file to detect threats
    """
    file_path = log_entry.log_file.path
    detected_threats = []
    ip_tracker = defaultdict(int)  # Count requests per IP (for DDoS detection)

    with open(file_path, 'r') as file:
        for line in file:
            # Extract IP if present
            ip_match = re.search(r"(\b(?:\d{1,3}\.){3}\d{1,3}\b)", line)
            ip_address = ip_match.group(0) if ip_match else None

            for threat, (pattern, severity) in THREAT_PATTERNS.items():
                if re.search(pattern, line, re.IGNORECASE):
                    detected_threats.append(
                        ThreatDetection(log=log_entry, ip_address=ip_address, threat_type=threat, severity=severity)
                    )
                    
                    # Count repeated IPs (DDoS detection)
                    if threat == "DDoS Attack" and ip_address:
                        ip_tracker[ip_address] += 1
                        if ip_tracker[ip_address] > 10:  # More than 10 requests from the same IP
                            detected_threats.append(
                                ThreatDetection(log=log_entry, ip_address=ip_address, threat_type="DDoS Flooding", severity="High")
                            )

    ThreatDetection.objects.bulk_create(detected_threats)
    log_entry.analyzed = True
    log_entry.save()



from django.core.paginator import Paginator
from django.db.models import Count
import os
import json
from django.http import JsonResponse



def log_analysis_report(request):
    """
    Display all uploaded logs and detected threats.
    Each log now includes a link to its corresponding threat frequency chart and the specific log section where threats were detected.
    """
    logs = ThreatLog.objects.prefetch_related('threats')  

    return render(request, 'log_report.html', {'logs': logs})





def threat_frequency_chart(request, log_id):
    log = get_object_or_404(ThreatLog, id=log_id)  # Removed user filter

    # Aggregate threat data
    threat_counts = (
        log.threats.values('threat_type')
        .annotate(count=Count('threat_type'))
        .order_by('-count')
    )

    labels = [threat["threat_type"] for threat in threat_counts]
    counts = [threat["count"] for threat in threat_counts]

    return render(request, "threat_chart.html", {
        "log_name": log.log_file.name.split('/')[-1],  # Only show the filename
        "labels": labels,
        "counts": counts
    })


import requests
import ipaddress
from django.conf import settings
from django.shortcuts import render
from .models import IPReputation
from .forms import ReputationCheckForm





def is_public_ip(ip):
    """Returns True if the IP is public, False if it's private or invalid."""
    try:
        return ipaddress.ip_address(ip).is_global  # Checks if the IP is public
    except ValueError:
        return False  # Invalid IP format

def check_ip_reputation(ip):
    """Check IP reputation using AbuseIPDB API."""
    if not is_public_ip(ip):
        return None, "Private or invalid IP. Only public IPs can be checked."

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": settings.ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        response = requests.get(url, headers=headers, params=params)
        data = response.json()
        print("DEBUG: AbuseIPDB Raw Response", data)  # Debugging line

        if response.status_code == 200 and "data" in data:
            reputation_score = data["data"].get("abuseConfidenceScore", 0)
            blacklisted = reputation_score > 50  # Consider blacklisted if score > 50

            message = "This IP is blacklisted or not safe." if blacklisted else "This IP is safe."
            
            return {
                "id": ip,
                "reputation_score": reputation_score,
                "blacklisted": blacklisted,
                "message": message,
            }, None
        else:
            return None, f"Error: {data.get('errors', 'Unknown error')}"
    except Exception as e:
        return None, str(e)


def check_domain_reputation(domain):
    """Check domain reputation using VirusTotal API."""
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        data = response.json()
        print("DEBUG: VirusTotal Raw Response", data)  # Debugging line

        if response.status_code == 200 and "data" in data:
            attributes = data["data"].get("attributes", {})
            reputation_score = attributes.get("last_analysis_stats", {}).get("malicious", 0)
            blacklisted = reputation_score > 0  # If malicious count > 0, it's blacklisted

            message = "This domain is blacklisted or not safe." if blacklisted else "This domain is safe."
            
            return {
                "id": domain,
                "reputation_score": reputation_score,
                "blacklisted": blacklisted,
                "message": message,
            }, None
        else:
            return None, f"Error: {data.get('error', 'Unknown error')}"
    except Exception as e:
        return None, str(e)



def check_reputation(request):
    """Handle reputation check for IP, domain, and log file uploads."""
    rep_form = ReputationCheckForm()
    log_form = LogUploadForm()
    result = None
    error = None
    is_ip = False  

    if request.method == "POST":
        if 'query' in request.POST:  # Handle IP/Domain Check
            rep_form = ReputationCheckForm(request.POST)
            if rep_form.is_valid():
                query = rep_form.cleaned_data["query"]
                try:
                    ipaddress.ip_address(query)
                    is_ip = True
                except ValueError:
                    is_ip = False
                
                if is_ip:
                    result, error = check_ip_reputation(query)
                    template_name = "ip_result.html"
                else:
                    result, error = check_domain_reputation(query)
                    template_name = "domain_result.html"
                
                if result:
                    IPReputation.objects.update_or_create(
                        ip_address=query if is_ip else None,
                        domain=query if not is_ip else None,
                        defaults={
                            "reputation_score": result.get("reputation_score", 0),
                            "blacklisted": result.get("blacklisted", False),
                        },
                    )
                
                # Redirect to the respective result page
                return render(
                    request, 
                    template_name,
                    {
                        "query": query,
                        "result": result,
                        "error": error,
                        "is_ip": is_ip,
                    }
                )
        
        
            
        elif 'log_file' in request.FILES:  # ✅ Fix Form Handling
            log_form = LogUploadForm(request.POST, request.FILES)
            if log_form.is_valid():
                log_entry = log_form.save(commit=False)
                # Removed: log_entry.user = request.user
                log_entry.save()
                analyze_logs(log_entry)
                return redirect('log_analysis_report')

    return render(
        request,
        "reputation_check.html",
        {
            "rep_form": rep_form,
            "log_form": log_form,
            "result": None,
            "error": None,
        },
    )


@login_required(login_url='user_login')
def delete_analysis(request, id):  # This now correctly receives 'id'
    user = get_object_or_404(CustomUser, id=id)
    user.delete()
    messages.success(request, "Event deleted successfully!")
    return redirect('user_list_view')
   
def detailed_log_analysis(request):
    logs = ThreatLog.objects.filter(user=request.user).order_by('-uploaded_at')
    
    print(f"Logs Found: {logs.exists()}")  

    log_data = []

    if logs.exists():
        latest_log = logs.first()  
       
        print(f"Opening Log File: {latest_log.log_file}")

        with latest_log.log_file.open(mode='r') as file:  
            file_content = file.read()
            
            
            if isinstance(file_content, bytes):
                file_content = file_content.decode('utf-8')

            
            print(f"File Content Preview:\n{file_content[:500]}")  

            reader = csv.reader(io.StringIO(file_content))  

            try:
                next(reader)  
                for row in reader:
                    print(f"Parsed Row: {row}") 

                    
                    if len(row) != 6:
                        print(f"⚠️ Skipping invalid row (Expected 6 columns, got {len(row)}): {row}")
                        continue

                    ip, timestamp, method, url, status, response_size = row

                   
                    threat_level = "✅ Normal"
                    if status == "401":
                        threat_level = "⚠️ Possible Brute Force"
                    elif status == "403":
                        threat_level = "⚠️ Unauthorized Admin Access"
                    elif status == "404":
                        threat_level = "⚠️ Scanner/Bot Activity"
                    elif status == "200" and url == "/login":
                        threat_level = "✅ Successful Login"

                    log_data.append({
                        "ip": ip,
                        "timestamp": timestamp,
                        "method": method,
                        "url": url,
                        "status": status,
                        "threat_level": threat_level
                    })
            except Exception as e:
                print(f"⚠️ Error processing CSV file: {e}")

    
    print(f"Processed Log Entries: {len(log_data)}")  

    return render(request, 'detailed_log.html', {"log_data": log_data})


from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponse
from .models import ThreatDetection, ThreatLog
from .forms import ThreatDetectionForm 

def threat_list(request):
    threats = ThreatDetection.objects.all()
    return render(request, 'threat_list.html', {'threats': threats})

# ✅ Add a new threat detection
def add_threat(request):
    if request.method == "POST":
        form = ThreatDetectionForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('threat_list')  # Redirect to the list page
    else:
        form = ThreatDetectionForm()
    return render(request, 'add_threat.html', {'form': form})

# ✅ Update an existing threat detection
def update_threat(request, threat_id):
    threat = get_object_or_404(ThreatDetection, id=threat_id)
    if request.method == "POST":
        form = ThreatDetectionForm(request.POST, instance=threat)
        if form.is_valid():
            form.save()
            return redirect('threat_list')
    else:
        form = ThreatDetectionForm(instance=threat)
    return render(request, 'update_threat.html', {'form': form})

# ✅ Delete a threat detection
def delete_threat(request, threat_id):
    threat = get_object_or_404(ThreatDetection, id=threat_id)
    if request.method == "POST":
        threat.delete()
        return redirect('threat_list')
    return render(request, 'delete_threat.html', {'threat': threat})


def log_details(request):
    logs = ThreatLog.objects.all().order_by('-uploaded_at')
    threat_detections = ThreatDetection.objects.select_related('log').all()

    log_data = []
    threat_data = []

    if logs.exists():
        latest_log = logs.first()
        with latest_log.log_file.open(mode='r') as file:
            file_content = file.read()
            if isinstance(file_content, bytes):
                file_content = file_content.decode('utf-8')

            reader = csv.reader(io.StringIO(file_content))  
            next(reader)  # Skip header

            for row in reader:
                ip, timestamp, method, url, status, response_size = row
                log_data.append({
                    "ip": ip,
                    "timestamp": timestamp,
                    "method": method,
                    "url": url,
                    "status": status,
                })

    if threat_detections.exists():
        for threat in threat_detections:
            threat_data.append({
                "threat_type": threat.threat_type,
                "severity": threat.severity,
                "detected_at": threat.detected_at
            })

    return render(request, 'detailed_log_analysis.html', {
        "log_data": log_data,
        "threat_data": threat_data
    })



# @login_required
# def upload_log(request):
#     if request.method == 'POST':
#         form = ThreatLogForm(request.POST, request.FILES)
#         if form.is_valid():
#             log = form.save(commit=False)
#             log.user = request.user
#             log.save()
#             return redirect('dashboard')
#     else:
#         form = ThreatLogForm()
#     return render(request, 'upload_log.html', {'form': form})


@login_required
def report_incident(request):
    if request.method == 'POST':
        form = IncidentReportForm(request.POST)
        if form.is_valid():
            incident = form.save(commit=False)
            incident.user = request.user
            incident.save()
            return redirect('dashboard')
    else:
        form = IncidentReportForm()
    return render(request, 'report_incident.html', {'form': form})


def admin_view(request):
    """
    Renders the admin dashboard with threat statistics.
    """
    # 📊 Count total threats & severity levels
    total_threats = ThreatDetection.objects.count()
    high_severity = ThreatDetection.objects.filter(severity="High").count()
    medium_severity = ThreatDetection.objects.filter(severity="Medium").count()
    low_severity = ThreatDetection.objects.filter(severity="Low").count()

    # 📌 Count occurrences of each threat type
    threat_counts = ThreatDetection.objects.values('threat_type').annotate(count=Count('threat_type'))
    threat_labels = [item['threat_type'] for item in threat_counts]
    threat_values = [item['count'] for item in threat_counts]

    # 📅 Get latest threats
    latest_threats = ThreatDetection.objects.order_by('-detected_at')[:10]

    context = {
        "total_threats": total_threats,
        "high_severity": high_severity,
        "medium_severity": medium_severity,
        "low_severity": low_severity,
        "threat_labels": threat_labels,
        "threat_values": threat_values,
        "latest_threats": latest_threats,
    }

    return render(request, 'admin_view.html', context)


def test(request):
    return render(request,'test.html')

def reg(request):
    return render(request,'reg.html')


CustomUser = get_user_model()


def user_list_view(request):
    users = CustomUser.objects.all()
    return render(request, "admin_pages/user_list.html", {"users": users})

@login_required(login_url='user_login')
def delete_user(request, id):  # This now correctly receives 'id'
    user = get_object_or_404(CustomUser, id=id)
    user.delete()
    messages.success(request, "Event deleted successfully!")
    return redirect('user_list_view')


