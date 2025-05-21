from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import CustomUser
from .models import ThreatLog, IncidentReport, ThreatDetection, Enquiry
from .models import ThreatLog



class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = CustomUser
        fields = ["username", "email", "phone", "password1", "password2"]
        
        
class LogUploadForm(forms.ModelForm):
    class Meta:
        model = ThreatLog
        fields = ['log_file']

class IncidentReportForm(forms.ModelForm):
    class Meta:
        model = IncidentReport
        fields = ['title', 'description', 'status']
   
               
class ThreatDetectionForm(forms.ModelForm):
    class Meta:
        model = ThreatDetection
        fields = ['log', 'threat_type', 'severity']
        
               
class ReputationCheckForm(forms.Form):
    query = forms.CharField(
        max_length=255, 
        required=True, 
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "Enter IP or Domain"})
    )


class EnquiryForm(forms.ModelForm):
    class Meta:
        model = Enquiry
        fields = '__all__'