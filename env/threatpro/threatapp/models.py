from django.db import models

from django.contrib.auth.models import AbstractUser
# Create your models here.

class CustomUser(AbstractUser):
    phone = models.CharField(max_length=10, blank=True, null=True)

    def __str__(self):
        return self.username
    
# Create your models here.


class ThreatLog(models.Model): 
    log_file = models.FileField(upload_to='logs/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    analyzed = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.username} - {self.log_file.name} - {self.uploaded_at}"

 
 
class ThreatDetection(models.Model):
    log = models.ForeignKey(ThreatLog, on_delete=models.CASCADE, related_name="threats")
    ip_address = models.GenericIPAddressField(null=True, blank=True)  # New field for tracking IPs
    threat_type = models.CharField(max_length=200)
    severity = models.CharField(max_length=50, choices=[('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High')])
    detected_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.threat_type} - {self.severity} - {self.detected_at}"
    

class IPReputation(models.Model):
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    domain = models.CharField(max_length=255, null=True, blank=True)
    reputation_score = models.IntegerField(default=0)
    blacklisted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.ip_address if self.ip_address else self.domain
    

class IncidentReport(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField()
    status = models.CharField(max_length=50, choices=[('Open', 'Open'), ('Investigating', 'Investigating'), ('Resolved', 'Resolved')])
    reported_at = models.DateTimeField(auto_now_add=True)
    
    
class Enquiry(models.Model):
    name = models.CharField(max_length=100, blank=True, null=True)  
    email = models.EmailField(blank=True, null=True)
    phone = models.CharField(max_length=12, blank=True, null=True)
    message = models.TextField(blank=True, null=True)
    def __str__(self):
        return self.name 